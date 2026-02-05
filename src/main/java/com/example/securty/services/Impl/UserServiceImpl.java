package com.example.securty.services.Impl;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

import java.io.InputStream;
import java.net.HttpRetryException;
import java.nio.charset.StandardCharsets;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.securty.dtos.LoginRequest;
import com.example.securty.dtos.RegisterRequest;
import com.example.securty.dtos.Response;
import com.example.securty.dtos.UpdateRequest;
import com.example.securty.filter.JwtUtil;
import com.example.securty.models.User;
import com.example.securty.repositories.UserRepository;
import com.example.securty.services.IUserService;

import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class UserServiceImpl implements IUserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JavaMailSender mailSender;

    // inject backend URL from application.properties
    @Value("${url.backend}")
    private String backendUrl;

    @Override
    public Response<?> register(RegisterRequest registerRequest) {
        try {
            // Check request validity
            if (registerRequest.getUsername() == null || registerRequest.getPassword() == null
                    || registerRequest.getEmail() == null) {
                throw new HttpRetryException("Invalid registration data", HttpStatus.BAD_REQUEST.value());
            }
            // Check if user exists
            boolean userExists = userRepository.findByUsername(registerRequest.getUsername()).isPresent();
            if (userExists) {
                System.out.println("Username already taken: " + registerRequest.getUsername());
                throw new HttpRetryException("Username already taken", HttpStatus.BAD_REQUEST.value());
            }
            User.Role role = User.Role.USER;
            try {
                if (registerRequest.getRole() != null) {
                    role = User.Role.valueOf(registerRequest.getRole().toUpperCase());
                }
            } catch (IllegalArgumentException ignored) {
                role = User.Role.USER;
            }

            // IMPORTANT: constructor expects (username, password, email, role)
            User newUser = new User(registerRequest.getUsername(),
                    passwordEncoder.encode(registerRequest.getPassword()),
                    registerRequest.getEmail(),
                    role);

            userRepository.save(newUser);

            // Send welcome email (optional)
            try {
                MimeMessage message = mailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
                helper.setTo(newUser.getEmail());
                helper.setSubject("Welcome to Our Application");

                // Load HTML template from classpath and replace placeholders
                String htmlTemplate = "";
                try (InputStream is = getClass().getResourceAsStream("/templates/registration.html")) {
                    if (is != null) {
                        htmlTemplate = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                    }
                }

                String displayName = newUser.getFirstName() != null ? newUser.getFirstName() : newUser.getUsername();
                String loginLink = backendUrl; // you can change to a specific login path if needed

                String html = htmlTemplate
                        .replace("{{name}}", escapeHtml(displayName))
                        .replace("{{username}}", escapeHtml(newUser.getUsername()))
                        .replace("{{loginUrl}}", escapeHtml(loginLink));

                helper.setText(html, true); // true = HTML
                mailSender.send(message);
            } catch (Exception e) {
                // Log email sending failure but do not fail registration
                System.out.println("Failed to send welcome email: " + e.getMessage());
            }

            return new Response<>("User registered successfully", HttpStatus.OK.value());
        } catch (HttpRetryException e) {
            if (e.responseCode() == HttpStatus.BAD_REQUEST.value()) {
                return new Response<>(e.getMessage(), HttpStatus.BAD_REQUEST.value());
            } else {
                return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public Response<?> login(LoginRequest loginRequest) {
        try {
            if (loginRequest.getUsername() == null || loginRequest.getPassword() == null) {
                throw new HttpRetryException("Missing parameters", HttpStatus.BAD_REQUEST.value());
            }
            authenticationManager.authenticate(
                    new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(), loginRequest.getPassword()));
            // generate tokens map
            Map<String, Object> tokens = generateToken(loginRequest.getUsername());
            return new Response<>("Login successful", tokens, HttpStatus.OK.value());
        } catch (HttpRetryException e) {
            if (e.responseCode() == HttpStatus.BAD_REQUEST.value()) {
                return new Response<>(e.getMessage(), HttpStatus.BAD_REQUEST.value());
            } else {
                return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
            }
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    // refreshed:
    @Override
    public Response<?> refreshToken(String refreshToken) {
        try {
            String username = jwtUtil.extractUsername(refreshToken);
            if (username != null && jwtUtil.validateRefreshToken(refreshToken, username)) {
                Map<String, Object> tokens = generateTokenWithRefreshToken(username, refreshToken);
                return new Response<>("Token refreshed successfully", tokens, HttpStatus.OK.value());
            } else {
                return new Response<>("Invalid refresh token", HttpStatus.UNAUTHORIZED.value());
            }
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    // Forgot password:
    @Override
    public Response<?> forgotPassword(String username) {
        try {
            if (username == null || username.isEmpty()) {
                throw new HttpRetryException("Username is required", HttpStatus.BAD_REQUEST.value());
            }

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new Exception("User with given email not found"));

            String resetToken = generateResetPassword();

            // persist reset token + expiry (1 hour)
            user.setResetToken(resetToken);
            user.setResetTokenExpiry(Instant.now().plus(1, ChronoUnit.HOURS));
            userRepository.save(user);

            // use injected backendUrl (not the literal "$url.backend")
            String resetLink = backendUrl + "/api/v1" + "/auth/reset-password/" + resetToken;
            System.out.println("Reset link: " + resetLink);

            try {
                MimeMessage message = mailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
                helper.setTo(user.getEmail());
                helper.setSubject("Password Reset Request");
                String body = "Hello " + (user.getFirstName() != null ? user.getFirstName() : user.getUsername())
                        + ",\n\n"
                        + "We received a request to reset your password. Click the link below to reset it:\n\n"
                        + resetLink + "\n\n"
                        + "New password will be set to the token provided in the URL.\n\n"
                        + resetToken + "\n\n"
                        + "If you didn't request this, please ignore this email.\n\n"
                        + "Regards,\nYour App Team";
                helper.setText(body, false);
                mailSender.send(message);
            } catch (Exception mailEx) {
                return new Response<>("Failed to send email: " + mailEx.getMessage(),
                        HttpStatus.INTERNAL_SERVER_ERROR.value());
            }

            return new Response<>("Password reset link has been sent to your email", HttpStatus.OK.value());
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    // Implement resetPassword using stored token and expiry
    @Override
    public Response<?> resetPassword(String token) {
        try {
            if (token == null || token.isEmpty()) {
                return new Response<>("Missing parameters", HttpStatus.BAD_REQUEST.value());
            }

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
                return new Response<>("Unauthorized", HttpStatus.UNAUTHORIZED.value());
            }

            Object principal = auth.getPrincipal();
            String username;
            if (principal instanceof UserDetails userDetails) {
                username = userDetails.getUsername();
            } else {
                username = principal.toString();
            }

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new Exception("User not found"));

            if (user.getResetToken() == null || user.getResetTokenExpiry() == null) {
                return new Response<>("No reset request found", HttpStatus.BAD_REQUEST.value());
            }

            if (!token.equals(user.getResetToken())) {
                return new Response<>("Invalid reset token", HttpStatus.UNAUTHORIZED.value());
            }

            if (Instant.now().isAfter(user.getResetTokenExpiry())) {
                return new Response<>("Reset token expired", HttpStatus.UNAUTHORIZED.value());
            }

            // update password and clear token
            user.setPassword(passwordEncoder.encode(token));
            user.setResetToken(null);
            user.setResetTokenExpiry(null);
            userRepository.save(user);

            return new Response<>("Password has been reset successfully", HttpStatus.OK.value());
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public Response<?> me() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
                return new Response<>("Unauthorized", HttpStatus.UNAUTHORIZED.value());
            }

            Object principal = auth.getPrincipal();
            String username;
            if (principal instanceof UserDetails userDetails) {
                username = userDetails.getUsername();
            } else {
                username = principal.toString();
            }

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new Exception("User not found"));

            Map<String, Object> userData = new HashMap<>();
            userData.put("id", user.getId());
            userData.put("username", user.getUsername());
            userData.put("email", user.getEmail());
            userData.put("role", user.getRole().name());
            userData.put("first_name", user.getFirstName() != null ? user.getFirstName() : "");
            userData.put("last_name", user.getLastName() != null ? user.getLastName() : "");
            userData.put("gender", user.getGender().name() != null ? user.getGender().name() : "");
            userData.put("phone_number", user.getPhoneNumber() != null ? user.getPhoneNumber() : "");
            userData.put("address", user.getAddress() != null ? user.getAddress() : "");
            userData.put("profile_picture", user.getProfilePicture() != null ? user.getProfilePicture() : "");

            return new Response<>("User details fetched successfully", userData, HttpStatus.OK.value());
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    // Simple HTML escape for placeholder values to avoid breaking the template
    private String escapeHtml(String s) {
        if (s == null)
            return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    @Override
    public Response<?> update(UpdateRequest updateRequest) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
                return new Response<>("Unauthorized", HttpStatus.UNAUTHORIZED.value());
            }

            Object principal = auth.getPrincipal();
            System.out.println("Principal: " + principal);
            String username;
            if (principal instanceof UserDetails userDetails) {
                username = userDetails.getUsername();
            } else {
                username = principal.toString();
            }

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new Exception("User not found"));

            // Update fields if provided
            if (updateRequest.getFirstName() != null)
                user.setFirstName(updateRequest.getFirstName());
            if (updateRequest.getLastName() != null)
                user.setLastName(updateRequest.getLastName());
            if (updateRequest.getGender() != null) {
                try {
                    user.setGender(User.Gender.valueOf(updateRequest.getGender().toUpperCase()));
                } catch (IllegalArgumentException ignored) {
                }
            }
            if (updateRequest.getPhoneNumber() != null)
                user.setPhoneNumber(updateRequest.getPhoneNumber());
            if (updateRequest.getAddress() != null)
                user.setAddress(updateRequest.getAddress());
            if (updateRequest.getProfilePicture() != null)
                user.setProfilePicture(updateRequest.getProfilePicture());
            if (updateRequest.getEmail() != null)
                user.setEmail(updateRequest.getEmail());

            userRepository.save(user);

            return new Response<>("User updated successfully", HttpStatus.OK.value());
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public Response<?> deleteUserById(Long id) {
        try {
            userRepository.deleteById(id);
            return new Response<>("User deleted successfully", HttpStatus.OK.value());
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public Response<?> getAllUsers() {
        try {
            var users = userRepository.findAll();
            return new Response<>("Users fetched successfully", users, HttpStatus.OK.value());
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public Response<?> logout(HttpServletResponse response) {
        try {
            // clear SecurityContext
            SecurityContextHolder.clearContext();

            // overwrite cookies to remove them in browser
            Cookie access = new Cookie("access_token", "");
            access.setHttpOnly(true);
            access.setPath("/");
            access.setMaxAge(0); // expire immediately
            // access.setSecure(true); // optional: require HTTPS
            response.addCookie(access);

            Cookie refresh = new Cookie("refresh_token", "");
            refresh.setHttpOnly(true);
            refresh.setPath("/");
            refresh.setMaxAge(0);
            // refresh.setSecure(true);
            response.addCookie(refresh);

            return new Response<>("Logout successful", HttpStatus.OK.value());
        } catch (Exception e) {
            return new Response<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    // corrected: use java.util.Map and proper keys
    public Map<String, Object> generateToken(String username) {
        String accessToken = jwtUtil.generateToken(username);
        String refreshToken = jwtUtil.generateRefreshToken(username);
        Map<String, Object> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        return tokens;
    }

    private Map<String, Object> generateTokenWithRefreshToken(String username, String refreshToken) {

        String accessToken, newRefreshToken;

        boolean expired = jwtUtil.isRefreshTokenExpired(refreshToken);
        if (expired) {
            newRefreshToken = jwtUtil.generateRefreshToken(username);
            accessToken = jwtUtil.generateToken(username);
        } else {
            accessToken = jwtUtil.generateToken(username);
            newRefreshToken = refreshToken;
        }

        Map<String, Object> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", newRefreshToken);
        return tokens;

    }

    private String generateResetPassword() {
        String chars = "abcdefghiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
        // For simplicity, we'll just return a dummy token.
        String token = "";
        for (int i = 0; i < 30; i++) {
            int idx = (int) (Math.random() * chars.length());
            token += chars.charAt(idx);
        }
        // In a real application, generate a secure token and store it with an
        // expiration.
        return token;
    }
}

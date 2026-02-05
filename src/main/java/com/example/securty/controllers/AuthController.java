package com.example.securty.controllers;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.securty.dtos.LoginRequest;
import com.example.securty.dtos.RegisterRequest;
import com.example.securty.dtos.Response;
import com.example.securty.services.IUserService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private IUserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        Response<?> resp = userService.register(req);
        // return the service response so errors (like "Username already taken") are propagated
        if (resp == null) {
            return ResponseEntity.status(500).body(new Response<>("Internal error", 500));
        }
        return ResponseEntity.status(resp.getStatus()).body(resp);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response, HttpServletRequest request) {
        Response<?> resp = userService.login(req);
        // if service returned tokens, set cookies
        if (resp != null && resp.getData() instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> tokens = (Map<String, Object>) resp.getData();
            String access = (String) tokens.get("access_token");
            String refresh = (String) tokens.get("refresh_token");
            boolean secure = request.isSecure();
            if (access != null) {
                Cookie c = new Cookie("access_token", access);
                c.setHttpOnly(true);
                c.setPath("/");
                c.setSecure(secure);
                c.setMaxAge(24 * 3600); // 24 hours
                response.addCookie(c);
            }
            if (refresh != null) {
                Cookie rc = new Cookie("refresh_token", refresh);
                rc.setHttpOnly(true);
                rc.setPath("/");
                rc.setSecure(secure);
                rc.setMaxAge(7 * 24 * 3600); // 7 days
                response.addCookie(rc);
            }

            return ResponseEntity.status(resp.getStatus()).body(resp);
        
        }
        // return the service response (it contains tokens and any error info)
        return ResponseEntity.status(resp.getStatus()).body(resp);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> requestBody, HttpServletResponse response,
            HttpServletRequest request) {
        String refreshToken = requestBody.get("refresh_token");
        Response<?> resp = userService.refreshToken(refreshToken);
        // if service returned new tokens, set cookies
        if (resp != null && resp.getData() instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> tokens = (Map<String, Object>) resp.getData();
            String access = (String) tokens.get("access_token");
            String refresh = (String) tokens.get("refresh_token");
            boolean secure = request.isSecure();
            if (access != null) {
                Cookie c = new Cookie("access_token", access);
                c.setHttpOnly(true);
                c.setPath("/");
                c.setSecure(secure);
                c.setMaxAge(24 * 3600); // 24 hours
                response.addCookie(c);
            }
            if (refresh != null) {
                Cookie rc = new Cookie("refresh_token", refresh);
                rc.setHttpOnly(true);
                rc.setPath("/");
                rc.setSecure(secure);
                rc.setMaxAge(7 * 24 * 3600); // 7 days
                response.addCookie(rc);
            }
        }
        return ResponseEntity.status(resp.getStatus()).body(resp);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> requestBody) {
        String username = requestBody.get("username");
        Response<?> resp = userService.forgotPassword(username);
        return ResponseEntity.status(resp.getStatus()).body(resp);
    }

    @PostMapping("/reset-password/{token}")
    public ResponseEntity<?> resetPassword(@PathVariable String token) {
        Response<?> resp = userService.resetPassword(token);
        return ResponseEntity.status(resp.getStatus()).body(resp);
    }

    @GetMapping("/me")
    public ResponseEntity<?> me() {
        Response<?> resp = userService.me();
        return ResponseEntity.status(resp.getStatus()).body(resp);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Response<?> resp = userService.logout(response);
        return ResponseEntity.status(resp.getStatus()).body(resp);
    }
}

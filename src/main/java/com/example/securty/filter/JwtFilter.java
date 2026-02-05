package com.example.securty.filter;

import java.io.IOException;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.securty.repositories.UserRepository;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String token = null;
        String username = null;

        // 1) Try Authorization header
        final String authHeader = req.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        // 2) Fallback: try cookies (access_token)
        if (token == null) {
            Cookie[] cookies = req.getCookies();
            if (cookies != null) {
                for (Cookie c : cookies) {
                    if ("access_token".equals(c.getName())) {
                        token = c.getValue();
                        break;
                    }
                }
            }
        }

        // 3) Validate and set Authentication if possible
        if (token != null) {
            try {
                username = jwtUtil.extractUsername(token);
            } catch (JwtException | IllegalArgumentException e) {
                // invalid token -> ignore and continue chain (remain unauthenticated)
                username = null;
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // load user from DB and create UserDetails
            var userOpt = userRepository.findByUsername(username);
            if (userOpt.isPresent() && jwtUtil.validateToken(token, username)) {
                var u = userOpt.get();
                UserDetails ud = new org.springframework.security.core.userdetails.User(
                        u.getUsername(),
                        u.getPassword(),
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + u.getRole().name()))
                );
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(ud, null, ud.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        chain.doFilter(req, res);
    }
}

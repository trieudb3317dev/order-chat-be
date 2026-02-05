package com.example.securty.dtos;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {
    private String refreshToken;
    private String token;
    private String message;

    public AuthResponse() {
    }

    public AuthResponse(String token, String refreshToken, String message) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.message = message;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String t) {
        this.token = t;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String m) {
        this.message = m;
    }
}

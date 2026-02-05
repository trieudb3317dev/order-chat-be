package com.example.securty.services;

import com.example.securty.dtos.LoginRequest;
import com.example.securty.dtos.RegisterRequest;
import com.example.securty.dtos.Response;
import com.example.securty.dtos.UpdateRequest;

import jakarta.servlet.http.HttpServletResponse;

public interface IUserService {

    Response<?> register(RegisterRequest registerRequest);

    Response<?> login(LoginRequest loginRequest);

    Response<?> refreshToken(String refreshToken);

    Response<?> forgotPassword(String username);

    // reset password using token sent in email
    Response<?> resetPassword(String token);

    Response<?> me();

    // added: logout should accept HttpServletResponse to clear cookies
    Response<?> logout(HttpServletResponse response);

    // edited: me method to fetch user details
    Response<?> update(UpdateRequest updateRequest);

    // added: delete user by id
    Response<?> deleteUserById(Long id);

    // added: fetch all users (admin only)
    Response<?> getAllUsers();
}

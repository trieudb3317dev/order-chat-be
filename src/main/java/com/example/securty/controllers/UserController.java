package com.example.securty.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.securty.dtos.Response;
import com.example.securty.dtos.UpdateRequest;
import com.example.securty.services.IUserService;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @Autowired
    private IUserService userService;

    @PutMapping("/update")
    public Response<?> updateUserDetails(@RequestBody UpdateRequest req) {
        try {
            Response<?> resp = userService.update(req);
            return new Response<>("User details updated successfully", resp.getData(), 200);
        } catch (Exception e) {
            return new Response<>("Failed to update user details: " + e.getMessage(), 500);
        }
    }
}

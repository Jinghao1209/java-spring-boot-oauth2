package com.example.oauth2.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// /auth/user
@RestController
public class AuthController {
    @GetMapping("/user")
    public String user(HttpServletRequest request) {
        return null; // TODO: custom return value
    }
}

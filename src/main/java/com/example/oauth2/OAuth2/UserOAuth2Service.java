package com.example.oauth2.OAuth2;

import org.springframework.stereotype.Service;

@Service
public class UserOAuth2Service {
    public void processOAuthPostLogin(String email) {
        System.out.println("Email: " + email);
    }
}

package com.jonathan.springsection1.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {

    @GetMapping("/welcome")
    public  String sayWelcome() {
        return "Welcome to Spring Boot Application with security";
    }
}

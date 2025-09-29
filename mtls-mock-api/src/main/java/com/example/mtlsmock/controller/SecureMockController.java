package com.example.mtlsmock.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/secure")
public class SecureMockController {

    @GetMapping("/hello")
    public ResponseEntity<String> hello(Principal principal) {
        return ResponseEntity.ok("✅ Hola " + principal.getName() +
                ", conexión mTLS establecida con éxito!");
    }
}

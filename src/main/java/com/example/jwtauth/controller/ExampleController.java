package com.example.jwtauth.controller;

import com.example.jwtauth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/example")
@RequiredArgsConstructor
@Tag(name = "Примеры API")
public class ExampleController {

    private final UserService service;

    @GetMapping
    @Operation(summary = "Доступен только авторизованным пользователям")
    public Map<String, String> example() {
        return Map.of("message", "Hello, world!", "access", "authenticated");
    }

    @GetMapping("/admin")
    @Operation(summary = "Доступен только авторизованным пользователям с ролью ADMIN")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> exampleAdmin() {
        return Map.of("message", "Hello, admin!", "access", "admin");
    }

    @GetMapping("/get-admin")
    @Operation(summary = "Получить роль ADMIN (для демонстрации)")
    public Map<String, String> getAdmin() {
        service.getAdmin();
        return Map.of("message", "Admin role granted! Refresh page and try admin endpoint.");
    }
}
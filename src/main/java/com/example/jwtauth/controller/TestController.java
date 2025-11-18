package com.example.jwtauth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
@Tag(name = "Тестовые эндпоинты")
public class TestController {

    @GetMapping("/public")
    @Operation(summary = "Публичный эндпоинт - доступен всем")
    public Map<String, String> publicEndpoint() {
        return Map.of(
                "message", "Это публичный эндпоинт",
                "status", "success",
                "access", "public"
        );
    }

    @GetMapping("/protected")
    @Operation(summary = "Защищенный эндпоинт - требует аутентификации")
    public Map<String, String> protectedEndpoint() {
        return Map.of(
                "message", "Это защищенный эндпоинт",
                "status", "success",
                "access", "authenticated"
        );
    }
}
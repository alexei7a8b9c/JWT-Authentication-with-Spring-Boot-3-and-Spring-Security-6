package com.example.jwtauth.controller;

import com.example.jwtauth.service.TokenBlacklistService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final TokenBlacklistService tokenBlacklistService;

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        log.info("API logout endpoint called");

        // Извлекаем токен из запроса
        String token = extractTokenFromRequest(request);
        if (token != null && !token.isEmpty()) {
            tokenBlacklistService.blacklistToken(token);
            log.info("✅ Token blacklisted via API logout");
        }

        // Очищаем куки
        clearTokenCookies(response);

        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("message", "Logout successful");
        responseBody.put("redirect", "/");

        return ResponseEntity.ok().body(responseBody);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        // Из заголовка Authorization
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        // Из куки
        if (request.getCookies() != null) {
            for (var cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void clearTokenCookies(HttpServletResponse response) {
        // Access token
        var accessTokenCookie = new jakarta.servlet.http.Cookie("accessToken", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);
        response.addCookie(accessTokenCookie);

        // Refresh token
        var refreshTokenCookie = new jakarta.servlet.http.Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);

        // CSRF token
        var csrfTokenCookie = new jakarta.servlet.http.Cookie("XSRF-TOKEN", null);
        csrfTokenCookie.setHttpOnly(false);
        csrfTokenCookie.setSecure(false);
        csrfTokenCookie.setPath("/");
        csrfTokenCookie.setMaxAge(0);
        response.addCookie(csrfTokenCookie);
    }
}
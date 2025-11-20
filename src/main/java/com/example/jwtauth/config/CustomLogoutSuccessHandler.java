package com.example.jwtauth.config;

import com.example.jwtauth.service.TokenBlacklistService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    private final TokenBlacklistService tokenBlacklistService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException {

        log.info("=== SPRING SECURITY LOGOUT HANDLER ===");

        String token = extractTokenFromRequest(request);
        if (token != null && !token.isEmpty()) {
            tokenBlacklistService.blacklistToken(token);
            log.info("✅ Token blacklisted during Spring Security logout");
        }

        clearTokenCookies(response);
        log.info("✅ Token cookies cleared");

        if (isWebRequest(request)) {
            response.sendRedirect("/?logout=true");
        } else {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("message", "Logout successful");
            responseBody.put("redirect", "/");
            response.getWriter().write(objectMapper.writeValueAsString(responseBody));
        }

        log.info("✅ Spring Security logout completed successfully");
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        // Пробуем извлечь из заголовка Authorization
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        // Пробуем извлечь из куки
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("accessToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void clearTokenCookies(HttpServletResponse response) {
        // Очищаем access token cookie
        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);
        response.addCookie(accessTokenCookie);

        // Очищаем refresh token cookie
        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);

        // Очищаем CSRF token cookie
        Cookie csrfTokenCookie = new Cookie("XSRF-TOKEN", null);
        csrfTokenCookie.setHttpOnly(false);
        csrfTokenCookie.setSecure(false);
        csrfTokenCookie.setPath("/");
        csrfTokenCookie.setMaxAge(0);
        response.addCookie(csrfTokenCookie);
    }

    private boolean isWebRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        String requestUri = request.getRequestURI();

        return acceptHeader != null && acceptHeader.contains("text/html") ||
                requestUri.startsWith("/") && !requestUri.startsWith("/api/");
    }
}
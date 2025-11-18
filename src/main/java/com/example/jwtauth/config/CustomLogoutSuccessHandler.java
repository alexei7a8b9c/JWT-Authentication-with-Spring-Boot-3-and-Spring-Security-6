package com.example.jwtauth.config;

import com.example.jwtauth.service.TokenBlacklistService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    private final TokenBlacklistService tokenBlacklistService;

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

        clearTokenCookie(response);
        log.info("✅ Token cookie cleared");

        if (isWebRequest(request)) {
            response.sendRedirect("/?logout=true");
        } else {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.getWriter().write("{\"message\": \"Logout successful\"}");
        }

        log.info("✅ Spring Security logout completed successfully");
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private void clearTokenCookie(HttpServletResponse response) {
        Cookie cookie1 = new Cookie("token", null);
        cookie1.setHttpOnly(true);
        cookie1.setSecure(false);
        cookie1.setPath("/");
        cookie1.setMaxAge(0);
        response.addCookie(cookie1);

        Cookie cookie2 = new Cookie("token", null);
        cookie2.setPath("/");
        cookie2.setDomain("localhost");
        cookie2.setMaxAge(0);
        response.addCookie(cookie2);
    }

    private boolean isWebRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        String requestUri = request.getRequestURI();

        return acceptHeader != null && acceptHeader.contains("text/html") ||
                requestUri.startsWith("/") && !requestUri.startsWith("/api/");
    }
}
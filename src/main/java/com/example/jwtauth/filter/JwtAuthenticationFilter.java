package com.example.jwtauth.filter;

import com.example.jwtauth.service.JwtService;
import com.example.jwtauth.service.TokenBlacklistService;
import com.example.jwtauth.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;
    private final TokenBlacklistService tokenBlacklistService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String requestPath = request.getRequestURI();
        String userAgent = request.getHeader("User-Agent");
        String ipAddress = getClientIpAddress(request);

        // Логирование всех запросов к защищенным endpoint'ам
        log.debug("Auth attempt: {} from IP: {}, User-Agent: {}",
                requestPath, ipAddress, userAgent);

        if (isPublicEndpoint(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = extractTokenFromHeader(request);
        if (StringUtils.isEmpty(jwt)) {
            jwt = extractTokenFromCookie(request);
        }

        if (StringUtils.isEmpty(jwt)) {
            log.warn("No JWT token found for protected endpoint: {} from IP: {}", requestPath, ipAddress);
            handleUnauthorized(request, response, "No token found");
            return;
        }

        // УСИЛЕННАЯ ПРОВЕРКА BLACKLIST
        if (tokenBlacklistService.isTokenBlacklisted(jwt)) {
            log.warn("🚫 BLACKLISTED token used for: {} from IP: {}", requestPath, ipAddress);
            // Принудительно очищаем куки и редиректим
            deleteAllTokenCookies(response);
            handleUnauthorized(request, response, "Token blacklisted");
            return;
        }

        // ПРОВЕРКА ВАЛИДНОСТИ ТОКЕНА
        String username = null;
        try {
            if (!jwtService.validateAccessToken(jwt)) {
                log.warn("Invalid access token for: {} from IP: {}", requestPath, ipAddress);
                deleteAllTokenCookies(response);
                handleUnauthorized(request, response, "Invalid access token");
                return;
            }
            username = jwtService.extractUserNameFromAccessToken(jwt);
            log.debug("Token validated for user: {}", username);
        } catch (Exception e) {
            log.warn("Invalid JWT token for: {} from IP: {} - Error: {}", requestPath, ipAddress, e.getMessage());
            deleteAllTokenCookies(response);
            handleUnauthorized(request, response, "Invalid token");
            return;
        }

        if (StringUtils.isNotEmpty(username) &&
                SecurityContextHolder.getContext().getAuthentication() == null) {

            try {
                UserDetails userDetails = userService
                        .userDetailsService()
                        .loadUserByUsername(username);

                SecurityContext context = SecurityContextHolder.createEmptyContext();

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                context.setAuthentication(authToken);
                SecurityContextHolder.setContext(context);
                log.debug("✅ Authenticated user: {} for: {} from IP: {}", username, requestPath, ipAddress);

            } catch (Exception e) {
                log.warn("Authentication failed for user: {} from IP: {}", username, ipAddress);
                deleteAllTokenCookies(response);
                handleUnauthorized(request, response, "Authentication failed");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromHeader(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (StringUtils.isNotEmpty(authHeader) && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            log.debug("Token extracted from header, length: {}", token.length());
            return token;
        }
        return null;
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    String token = cookie.getValue();
                    log.debug("Token extracted from cookie, length: {}", token.length());
                    return token;
                }
            }
        }
        log.debug("No accessToken cookie found");
        return null;
    }

    // ОБНОВЛЕНО: Полная очистка всех кук
    private void deleteAllTokenCookies(HttpServletResponse response) {
        String[] cookieNames = {"accessToken", "refreshToken", "XSRF-TOKEN", "JSESSIONID"};

        for (String cookieName : cookieNames) {
            Cookie cookie = new Cookie(cookieName, "");
            cookie.setPath("/");
            cookie.setMaxAge(0);
            cookie.setSecure(false); // Для localhost development
            if ("accessToken".equals(cookieName) || "refreshToken".equals(cookieName)) {
                cookie.setHttpOnly(true);
            } else {
                cookie.setHttpOnly(false);
            }
            response.addCookie(cookie);
            log.debug("Cookie deleted: {}", cookieName);
        }
        log.info("All authentication cookies cleared");
    }

    private void handleUnauthorized(HttpServletRequest request,
                                    HttpServletResponse response,
                                    String reason) throws IOException {
        String requestPath = request.getRequestURI();

        if (requestPath.startsWith("/api/")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Unauthorized\", \"reason\": \"" + reason + "\"}");
        } else {
            log.info("Redirecting to login from: {} - Reason: {}", requestPath, reason);
            // Принудительно очищаем куки перед редиректом
            deleteAllTokenCookies(response);
            response.sendRedirect("/login?logout=true");
        }
    }

    private boolean isPublicEndpoint(String path) {
        return path.equals("/") ||
                path.startsWith("/auth/") ||
                path.startsWith("/api/auth/") ||
                path.startsWith("/css/") ||
                path.startsWith("/js/") ||
                path.startsWith("/webjars/") ||
                path.equals("/login") ||
                path.equals("/register") ||
                path.startsWith("/swagger-ui/") ||
                path.startsWith("/v3/api-docs/") ||
                path.equals("/api/test/public") ||
                path.contains("favicon.ico");
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0];
        }
        return request.getRemoteAddr();
    }
}
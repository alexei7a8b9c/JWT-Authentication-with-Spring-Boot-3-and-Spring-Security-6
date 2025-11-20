package com.example.jwtauth.controller;

import com.example.jwtauth.dto.JwtAuthenticationResponse;
import com.example.jwtauth.dto.RefreshTokenRequest;
import com.example.jwtauth.dto.SignInRequest;
import com.example.jwtauth.dto.SignUpRequest;
import com.example.jwtauth.service.AuthenticationService;
import com.example.jwtauth.service.JwtService;
import com.example.jwtauth.service.TokenBlacklistService;
import com.example.jwtauth.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Controller
@RequiredArgsConstructor
@Slf4j
public class CookieJwtController {

    private final AuthenticationService authenticationService;
    private final TokenBlacklistService tokenBlacklistService;
    private final JwtService jwtService;
    private final UserService userService;

    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    @GetMapping("/")
    public String home(@CookieValue(value = "accessToken", defaultValue = "") String accessToken,
                       @CookieValue(value = "refreshToken", defaultValue = "") String refreshToken,
                       @RequestParam(value = "logout", required = false) String logout,
                       @RequestParam(value = "tokenExpired", required = false) String tokenExpired,
                       Model model) {
        boolean isAuthenticated = !accessToken.isEmpty() && isTokenValid(accessToken, refreshToken);
        model.addAttribute("isAuthenticated", isAuthenticated);

        if (logout != null) {
            model.addAttribute("logoutMessage", "Вы успешно вышли из системы.");
        }
        if (tokenExpired != null) {
            model.addAttribute("tokenExpiredMessage", "Сессия истекла. Пожалуйста, войдите снова.");
        }
        return "index";
    }

    @GetMapping("/login")
    public String loginPage(@CookieValue(value = "accessToken", defaultValue = "") String accessToken,
                            @CookieValue(value = "refreshToken", defaultValue = "") String refreshToken,
                            @RequestParam(value = "error", required = false) String error,
                            @RequestParam(value = "tokenExpired", required = false) String tokenExpired,
                            Model model) {

        if (!accessToken.isEmpty() && isTokenValid(accessToken, refreshToken)) {
            return "redirect:/dashboard";
        }

        model.addAttribute("signInRequest", new SignInRequest());
        if (error != null) {
            model.addAttribute("errorMessage", "Неверное имя пользователя или пароль");
        }
        if (tokenExpired != null) {
            model.addAttribute("tokenExpiredMessage", "Сессия истекла. Пожалуйста, войдите снова.");
        }
        return "login";
    }

    @GetMapping("/register")
    public String registerPage(@CookieValue(value = "accessToken", defaultValue = "") String accessToken,
                               @CookieValue(value = "refreshToken", defaultValue = "") String refreshToken,
                               @RequestParam(value = "error", required = false) String error,
                               Model model) {

        if (!accessToken.isEmpty() && isTokenValid(accessToken, refreshToken)) {
            return "redirect:/dashboard";
        }

        model.addAttribute("signUpRequest", new SignUpRequest());
        if (error != null) {
            model.addAttribute("errorMessage", "Ошибка регистрации. Возможно, пользователь уже существует.");
        }
        return "register";
    }

    @GetMapping("/dashboard")
    public String dashboard(@CookieValue(value = "accessToken", defaultValue = "") String accessToken,
                            @CookieValue(value = "refreshToken", defaultValue = "") String refreshToken,
                            HttpServletResponse response,
                            Model model) {

        if (accessToken.isEmpty() && !refreshToken.isEmpty()) {
            try {
                JwtAuthenticationResponse newTokens = refreshTokens(refreshToken);
                if (newTokens != null) {
                    setSecureTokenCookies(response, newTokens);
                    model.addAttribute("accessToken", newTokens.getAccessToken());
                    model.addAttribute("refreshToken", newTokens.getRefreshToken());
                    model.addAttribute("username", jwtService.extractUserNameFromAccessToken(newTokens.getAccessToken()));
                    return "dashboard";
                }
            } catch (Exception e) {
                log.warn("Failed to refresh tokens: {}", e.getMessage());
                return "redirect:/login?tokenExpired=true";
            }
        }

        if (accessToken.isEmpty() || !isAccessTokenValid(accessToken)) {
            return "redirect:/login";
        }

        if (tokenBlacklistService.isTokenBlacklisted(accessToken)) {
            clearTokenCookies(response);
            return "redirect:/login";
        }

        try {
            String username = jwtService.extractUserNameFromAccessToken(accessToken);
            var userDetails = userService.userDetailsService().loadUserByUsername(username);

            model.addAttribute("accessToken", accessToken);
            model.addAttribute("refreshToken", refreshToken);
            model.addAttribute("username", username);

            return "dashboard";

        } catch (Exception e) {
            log.warn("Dashboard access failed: {}", e.getMessage());
            return "redirect:/login";
        }
    }

    @GetMapping("/admin")
    public String adminPage(@CookieValue(value = "accessToken", defaultValue = "") String accessToken,
                            @CookieValue(value = "refreshToken", defaultValue = "") String refreshToken,
                            HttpServletResponse response,
                            Model model) {

        String validatedAccessToken = validateAndRefreshTokens(accessToken, refreshToken, response);
        if (validatedAccessToken == null) {
            return "redirect:/login";
        }

        try {
            String username = jwtService.extractUserNameFromAccessToken(validatedAccessToken);
            var userDetails = userService.userDetailsService().loadUserByUsername(username);

            if (!userDetails.getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"))) {
                return "redirect:/dashboard";
            }

            model.addAttribute("username", username);
            return "admin";

        } catch (Exception e) {
            log.warn("Admin page access failed: {}", e.getMessage());
            return "redirect:/login";
        }
    }

    @PostMapping("/auth/web-signin")
    public String webSignIn(@Valid @ModelAttribute SignInRequest request,
                            HttpServletResponse response,
                            RedirectAttributes redirectAttributes) {
        try {
            JwtAuthenticationResponse authResponse = authenticationService.signIn(request);
            setSecureTokenCookies(response, authResponse);
            return "redirect:/dashboard";
        } catch (Exception e) {
            log.error("Web sign-in failed: {}", e.getMessage());
            redirectAttributes.addAttribute("error", "true");
            return "redirect:/login";
        }
    }

    @PostMapping("/auth/web-signup")
    public String webSignUp(@Valid @ModelAttribute SignUpRequest request,
                            HttpServletResponse response,
                            RedirectAttributes redirectAttributes) {
        try {
            JwtAuthenticationResponse authResponse = authenticationService.signUp(request);
            setSecureTokenCookies(response, authResponse);
            return "redirect:/dashboard";
        } catch (Exception e) {
            log.error("Web sign-up failed: {}", e.getMessage());
            redirectAttributes.addAttribute("error", "true");
            return "redirect:/register";
        }
    }

    @PostMapping("/auth/web-refresh")
    @ResponseBody
    public JwtAuthenticationResponse webRefresh(@CookieValue(value = "refreshToken", defaultValue = "") String refreshToken,
                                                HttpServletResponse response) {
        if (refreshToken.isEmpty()) {
            throw new RuntimeException("Refresh token not found");
        }

        try {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
            refreshRequest.setRefreshToken(refreshToken);

            JwtAuthenticationResponse newTokens = authenticationService.refreshToken(refreshRequest);
            setSecureTokenCookies(response, newTokens);
            return newTokens;

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            throw new RuntimeException("Token refresh failed");
        }
    }

    @PostMapping("/auth/web-logout")
    public String webLogout(@CookieValue(value = "refreshToken", defaultValue = "") String refreshToken,
                            HttpServletResponse response,
                            HttpServletRequest request) {

        try {
            if (!refreshToken.isEmpty()) {
                authenticationService.logout(refreshToken);
            }

            String accessToken = extractAccessTokenFromRequest(request);
            if (accessToken != null && !accessToken.isEmpty()) {
                tokenBlacklistService.blacklistToken(accessToken);
            }

        } catch (Exception e) {
            log.warn("Error during logout: {}", e.getMessage());
        } finally {
            clearTokenCookies(response);
        }

        return "redirect:/?logout=true";
    }

    @PostMapping("/auth/logout")
    public String webLogout(@CookieValue(value = "accessToken", defaultValue = "") String accessToken,
                            @CookieValue(value = "refreshToken", defaultValue = "") String refreshToken,
                            HttpServletResponse response,
                            HttpServletRequest request,
                            RedirectAttributes redirectAttributes) {

        log.info("Web logout called");

        try {
            // Добавляем access token в blacklist
            if (!accessToken.isEmpty()) {
                tokenBlacklistService.blacklistToken(accessToken);
                log.info("✅ Access token blacklisted during web logout");
            }

            // Отзываем refresh token
            if (!refreshToken.isEmpty()) {
                authenticationService.logout(refreshToken);
                log.info("✅ Refresh token revoked during web logout");
            }

        } catch (Exception e) {
            log.warn("Error during logout: {}", e.getMessage());
        } finally {
            // Всегда очищаем куки
            clearTokenCookies(response);
            log.info("✅ Cookies cleared during web logout");
        }

        return "redirect:/?logout=true";
    }

    @GetMapping("/token-info")
    @ResponseBody
    public Map<String, Object> getTokenInfoEndpoint(@CookieValue(value = "accessToken", defaultValue = "") String accessToken) {
        Map<String, Object> tokenInfo = new HashMap<>();

        if (accessToken.isEmpty()) {
            tokenInfo.put("error", "No token");
            return tokenInfo;
        }

        try {
            String username = jwtService.extractUserNameFromAccessToken(accessToken);
            boolean isValid = jwtService.validateAccessToken(accessToken);

            tokenInfo.put("username", username);
            tokenInfo.put("tokenType", "ACCESS");
            tokenInfo.put("length", accessToken.length());
            tokenInfo.put("isValid", isValid);

            return tokenInfo;
        } catch (Exception e) {
            tokenInfo.put("error", "Invalid token");
            return tokenInfo;
        }
    }

    // ========== SECURE COOKIE METHODS ==========

    private void setSecureTokenCookies(HttpServletResponse response, JwtAuthenticationResponse authResponse) {
        // Access Token - HTTP Only, Secure
        Cookie accessTokenCookie = createSecureCookie(
                "accessToken",
                authResponse.getAccessToken(),
                Math.toIntExact(authResponse.getAccessTokenExpiresIn())
        );
        response.addCookie(accessTokenCookie);

        // Refresh Token - HTTP Only, Secure
        Cookie refreshTokenCookie = createSecureCookie(
                "refreshToken",
                authResponse.getRefreshToken(),
                Math.toIntExact(authResponse.getRefreshTokenExpiresIn())
        );
        response.addCookie(refreshTokenCookie);

        // CSRF Token - доступен для JavaScript, но Secure
        Cookie csrfTokenCookie = new Cookie("XSRF-TOKEN", generateCsrfToken());
        csrfTokenCookie.setHttpOnly(false);
        csrfTokenCookie.setSecure(cookieSecure);
        csrfTokenCookie.setPath("/");
        csrfTokenCookie.setMaxAge(3600);
        response.addCookie(csrfTokenCookie);
    }

    private Cookie createSecureCookie(String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true); // Защита от XSS
        cookie.setSecure(cookieSecure); // Только HTTPS в production
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);

        // SameSite attribute
        if (cookieSecure) {
            // В production используем Strict
            cookie.setAttribute("SameSite", "Strict");
        } else {
            // В development Lax для удобства
            cookie.setAttribute("SameSite", "Lax");
        }

        return cookie;
    }

    private void clearTokenCookies(HttpServletResponse response) {
        // Очищаем access token
        Cookie accessTokenCookie = createSecureCookie("accessToken", "", 0);
        response.addCookie(accessTokenCookie);

        // Очищаем refresh token
        Cookie refreshTokenCookie = createSecureCookie("refreshToken", "", 0);
        response.addCookie(refreshTokenCookie);

        // Очищаем CSRF token
        Cookie csrfTokenCookie = new Cookie("XSRF-TOKEN", "");
        csrfTokenCookie.setHttpOnly(false);
        csrfTokenCookie.setSecure(cookieSecure);
        csrfTokenCookie.setPath("/");
        csrfTokenCookie.setMaxAge(0);
        response.addCookie(csrfTokenCookie);
    }

    private String generateCsrfToken() {
        return UUID.randomUUID().toString();
    }

    // ========== HELPER METHODS ==========

    private boolean isTokenValid(String accessToken, String refreshToken) {
        if (accessToken.isEmpty()) {
            return false;
        }

        if (jwtService.validateAccessToken(accessToken) &&
                !tokenBlacklistService.isTokenBlacklisted(accessToken)) {
            return true;
        }

        if (!refreshToken.isEmpty()) {
            try {
                return refreshTokens(refreshToken) != null;
            } catch (Exception e) {
                log.warn("Token refresh failed: {}", e.getMessage());
            }
        }

        return false;
    }

    private boolean isAccessTokenValid(String accessToken) {
        return jwtService.validateAccessToken(accessToken) &&
                !tokenBlacklistService.isTokenBlacklisted(accessToken);
    }

    private JwtAuthenticationResponse refreshTokens(String refreshToken) {
        try {
            RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
            refreshRequest.setRefreshToken(refreshToken);
            return authenticationService.refreshToken(refreshRequest);
        } catch (Exception e) {
            log.warn("Failed to refresh tokens: {}", e.getMessage());
            return null;
        }
    }

    private String validateAndRefreshTokens(String accessToken, String refreshToken, HttpServletResponse response) {
        if (isAccessTokenValid(accessToken)) {
            return accessToken;
        }

        if (!refreshToken.isEmpty()) {
            try {
                JwtAuthenticationResponse newTokens = refreshTokens(refreshToken);
                if (newTokens != null) {
                    setSecureTokenCookies(response, newTokens);
                    return newTokens.getAccessToken();
                }
            } catch (Exception e) {
                log.warn("Token refresh failed: {}", e.getMessage());
            }
        }

        return null;
    }

    private String extractAccessTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

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
}
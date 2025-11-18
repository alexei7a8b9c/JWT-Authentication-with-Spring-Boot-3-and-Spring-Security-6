package com.example.jwtauth.controller;

import com.example.jwtauth.dto.JwtAuthenticationResponse;
import com.example.jwtauth.dto.SignInRequest;
import com.example.jwtauth.dto.SignUpRequest;
import com.example.jwtauth.service.AuthenticationService;
import com.example.jwtauth.service.JwtService;
import com.example.jwtauth.service.TokenBlacklistService;
import com.example.jwtauth.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@Slf4j
public class CookieJwtController {

    private final AuthenticationService authenticationService;
    private final TokenBlacklistService tokenBlacklistService;
    private final JwtService jwtService;
    private final UserService userService;

    @GetMapping("/")
    public String home(@CookieValue(value = "token", defaultValue = "") String token,
                       @RequestParam(value = "logout", required = false) String logout,
                       Model model) {
        boolean isAuthenticated = !token.isEmpty();
        model.addAttribute("isAuthenticated", isAuthenticated);
        if (logout != null) {
            model.addAttribute("logoutMessage", "Вы успешно вышли из системы.");
        }
        return "index";
    }

    @GetMapping("/login")
    public String loginPage(@CookieValue(value = "token", defaultValue = "") String token,
                            @RequestParam(value = "error", required = false) String error,
                            Model model) {
        if (!token.isEmpty()) {
            return "redirect:/dashboard";
        }
        model.addAttribute("signInRequest", new SignInRequest());
        if (error != null) {
            model.addAttribute("errorMessage", "Неверное имя пользователя или пароль");
        }
        return "login";
    }

    @GetMapping("/register")
    public String registerPage(@CookieValue(value = "token", defaultValue = "") String token,
                               @RequestParam(value = "error", required = false) String error,
                               Model model) {
        if (!token.isEmpty()) {
            return "redirect:/dashboard";
        }
        model.addAttribute("signUpRequest", new SignUpRequest());
        if (error != null) {
            model.addAttribute("errorMessage", "Ошибка регистрации. Возможно, пользователь уже существует.");
        }
        return "register";
    }

    @GetMapping("/dashboard")
    public String dashboard(@CookieValue(value = "token", defaultValue = "") String token,
                            Model model) {
        if (token.isEmpty()) {
            return "redirect:/login";
        }

        if (tokenBlacklistService.isTokenBlacklisted(token)) {
            return "redirect:/login";
        }

        try {
            String username = jwtService.extractUserName(token);
            var userDetails = userService.userDetailsService().loadUserByUsername(username);

            if (!jwtService.isTokenValid(token, userDetails)) {
                return "redirect:/login";
            }

            model.addAttribute("token", token);
            model.addAttribute("username", username);
            return "dashboard";

        } catch (Exception e) {
            return "redirect:/login";
        }
    }

    @GetMapping("/admin")
    public String adminPage(@CookieValue(value = "token", defaultValue = "") String token, Model model) {
        if (token.isEmpty()) {
            return "redirect:/login";
        }
        return "admin";
    }

    @PostMapping("/auth/web-signin")
    public String webSignIn(@Valid @ModelAttribute SignInRequest request,
                            HttpServletResponse response) {
        try {
            JwtAuthenticationResponse authResponse = authenticationService.signIn(request);
            Cookie tokenCookie = createTokenCookie(authResponse.getToken());
            response.addCookie(tokenCookie);
            return "redirect:/dashboard";
        } catch (Exception e) {
            return "redirect:/login?error";
        }
    }

    @PostMapping("/auth/web-signup")
    public String webSignUp(@Valid @ModelAttribute SignUpRequest request,
                            HttpServletResponse response) {
        try {
            JwtAuthenticationResponse authResponse = authenticationService.signUp(request);
            Cookie tokenCookie = createTokenCookie(authResponse.getToken());
            response.addCookie(tokenCookie);
            return "redirect:/dashboard";
        } catch (Exception e) {
            return "redirect:/register?error";
        }
    }

    private Cookie createTokenCookie(String token) {
        Cookie tokenCookie = new Cookie("token", token);
        tokenCookie.setHttpOnly(true);
        tokenCookie.setSecure(false);
        tokenCookie.setPath("/");
        tokenCookie.setMaxAge(24 * 60 * 60);
        return tokenCookie;
    }
}
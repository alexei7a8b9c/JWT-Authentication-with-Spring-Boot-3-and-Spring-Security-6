package com.example.jwtauth.service;

import com.example.jwtauth.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class WebAuthService {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    public boolean login(String username, String password, HttpServletRequest request) {
        try {
            // Аутентифицируем пользователя
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // Устанавливаем аутентификацию в SecurityContext
            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authentication);

            // Сохраняем SecurityContext в сессию
            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

            // Сохраняем информацию о пользователе в сессии
            User user = userService.getByUsername(username);
            session.setAttribute("currentUser", user);
            session.setAttribute("username", user.getUsername());

            log.info("User {} logged in successfully", username);
            return true;
        } catch (Exception e) {
            log.error("Login failed for user: {}", username, e);
            return false;
        }
    }

    public void logout(HttpServletRequest request) {
        // Получаем сессию
        HttpSession session = request.getSession(false);

        if (session != null) {
            String username = (String) session.getAttribute("username");
            log.info("Logging out user: {}", username);

            // Очищаем сессию
            session.invalidate();
        }

        // Очищаем SecurityContext
        SecurityContextHolder.clearContext();

        // Удаляем JWT cookie на всякий случай
        log.info("Logout completed");
    }

    public boolean isAuthenticated(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null && session.getAttribute("username") != null;
    }

    public String getCurrentUsername(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null ? (String) session.getAttribute("username") : null;
    }
}
package com.example.jwtauth.service;

import com.example.jwtauth.dto.JwtAuthenticationResponse;
import com.example.jwtauth.dto.RefreshTokenRequest;
import com.example.jwtauth.dto.SignInRequest;
import com.example.jwtauth.dto.SignUpRequest;
import com.example.jwtauth.entity.RefreshToken;
import com.example.jwtauth.entity.Role;
import com.example.jwtauth.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final UserService userService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public JwtAuthenticationResponse signUp(SignUpRequest request) {
        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_USER)
                .build();

        userService.create(user);
        return generateTokenResponse(user);
    }

    @Transactional
    public JwtAuthenticationResponse signIn(SignInRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
        ));

        var user = userService
                .userDetailsService()
                .loadUserByUsername(request.getUsername());

        return generateTokenResponse((User) user);
    }

    @Transactional
    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        // Валидируем refresh токен
        if (!jwtService.validateRefreshToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        // Проверяем наличие токена в базе
        RefreshToken storedToken = refreshTokenService.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        // Проверяем, не отозван ли токен
        if (storedToken.isExpired() || storedToken.getRevoked()) {
            throw new RuntimeException("Refresh token expired or revoked");
        }

        // Отзываем использованный refresh токен
        refreshTokenService.revokeToken(storedToken);

        // Получаем пользователя и генерируем новые токены
        User user = storedToken.getUser();
        return generateTokenResponse(user);
    }

    @Transactional
    public void logout(String refreshToken) {
        if (refreshToken != null && !refreshToken.isEmpty()) {
            refreshTokenService.findByToken(refreshToken)
                    .ifPresent(refreshTokenService::revokeToken);
        }
    }

    private JwtAuthenticationResponse generateTokenResponse(User user) {
        var accessToken = jwtService.generateAccessToken(user);
        var refreshTokenEntity = refreshTokenService.createRefreshToken(user);

        return JwtAuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenEntity.getToken())
                .accessTokenExpiresIn(jwtService.getAccessTokenExpiration())
                .refreshTokenExpiresIn(jwtService.getRefreshTokenExpiration())
                .build();
    }
}
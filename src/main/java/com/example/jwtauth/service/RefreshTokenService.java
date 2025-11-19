package com.example.jwtauth.service;

import com.example.jwtauth.entity.RefreshToken;
import com.example.jwtauth.entity.User;
import com.example.jwtauth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    @Value("${token.expiration.refresh:2592000}") // 30 дней по умолчанию
    private Long refreshTokenDuration;

    @Transactional
    public RefreshToken createRefreshToken(User user) {
        // Отзываем все предыдущие токены пользователя
        revokeAllUserTokens(user);

        String token = UUID.randomUUID().toString();

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(token)
                .expiryDate(LocalDateTime.now().plusSeconds(refreshTokenDuration))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByTokenAndRevokedFalse(token);
    }

    @Transactional
    public void revokeToken(RefreshToken token) {
        token.setRevoked(true);
        refreshTokenRepository.save(token);
        log.info("Refresh token revoked for user: {}", token.getUser().getUsername());
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
        log.info("All refresh tokens revoked for user: {}", user.getUsername());
    }

    @Transactional
    @Scheduled(cron = "0 0 2 * * ?") // Каждый день в 2:00
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        refreshTokenRepository.deleteExpiredTokens(now);
        log.info("Cleaned up expired refresh tokens");
    }

    public boolean validateRefreshToken(String token) {
        return findByToken(token)
                .map(RefreshToken::isValid)
                .orElse(false);
    }
}
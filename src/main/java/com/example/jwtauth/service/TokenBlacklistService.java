package com.example.jwtauth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class TokenBlacklistService {

    private final ConcurrentHashMap<String, LocalDateTime> blacklistedTokens = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LocalDateTime> suspiciousIps = new ConcurrentHashMap<>();

    public void blacklistToken(String token) {
        if (token == null || token.isEmpty()) {
            log.warn("Attempt to blacklist null or empty token");
            return;
        }

        String tokenPreview = token.length() > 20 ? token.substring(0, 20) + "..." : token;
        blacklistedTokens.put(token, LocalDateTime.now().plusHours(24));
        log.info("✅ Token blacklisted: {}... (Total blacklisted: {})", tokenPreview, blacklistedTokens.size());

        // Дополнительное логирование для отладки
        log.debug("Blacklisted tokens: {}", blacklistedTokens.keySet());
    }

    public boolean isTokenBlacklisted(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        boolean isBlacklisted = blacklistedTokens.containsKey(token);
        if (isBlacklisted) {
            log.warn("🚫 Token check: BLACKLISTED - {}", token.substring(0, Math.min(20, token.length())) + "...");
        } else {
            log.debug("✅ Token check: VALID - {}", token.substring(0, Math.min(10, token.length())) + "...");
        }
        return isBlacklisted;
    }

    // ... остальные методы без изменений
}
package com.example.jwtauth.service;

import com.example.jwtauth.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
public class JwtService {

    @Value("${token.signing.key.access}")
    private String jwtAccessSigningKey;

    @Value("${token.signing.key.refresh}")
    private String jwtRefreshSigningKey;

    @Value("${token.expiration.access:300}") // 5 минут по умолчанию
    private Long accessTokenExpiration;

    @Value("${token.expiration.refresh:2592000}") // 30 дней по умолчанию
    private Long refreshTokenExpiration;

    // Access Token методы
    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        if (userDetails instanceof User customUserDetails) {
            claims.put("id", customUserDetails.getId());
            claims.put("email", customUserDetails.getEmail());
            claims.put("role", customUserDetails.getRole());
            claims.put("tokenType", "ACCESS");
        }
        return generateToken(claims, userDetails, getAccessSigningKey(), accessTokenExpiration);
    }

    public boolean validateAccessToken(String token) {
        return validateToken(token, getAccessSigningKey());
    }

    public String extractUserNameFromAccessToken(String token) {
        return extractClaim(token, Claims::getSubject, getAccessSigningKey());
    }

    // Refresh Token методы
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        if (userDetails instanceof User customUserDetails) {
            claims.put("id", customUserDetails.getId());
            claims.put("tokenType", "REFRESH");
        }
        return generateToken(claims, userDetails, getRefreshSigningKey(), refreshTokenExpiration);
    }

    public boolean validateRefreshToken(String token) {
        return validateToken(token, getRefreshSigningKey());
    }

    public String extractUserNameFromRefreshToken(String token) {
        return extractClaim(token, Claims::getSubject, getRefreshSigningKey());
    }

    // Общие методы для совместимости со старым кодом
    public String extractUsername(String token) {
        return extractUserNameFromAccessToken(token);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && validateAccessToken(token);
    }

    // Общие методы
    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails,
                                 Key signingKey, Long expiration) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .signWith(signingKey)
                .compact();
    }

    private boolean validateToken(String token, Key signingKey) {
        try {
            Jwts.parser()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers, Key signingKey) {
        final Claims claims = extractAllClaims(token, signingKey);
        return claimsResolvers.apply(claims);
    }

    private Claims extractAllClaims(String token, Key signingKey) {
        return Jwts.parser()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getPayload();
    }

    private Key getAccessSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtAccessSigningKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Key getRefreshSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtRefreshSigningKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Геттеры для времени жизни токенов
    public Long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public Long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }
}
package com.example.jwtauth.util;

import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

public class KeyGenerator {
    public static void main(String[] args) {
        // Генерация ключа для access токенов
        SecretKey accessKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS512);
        String accessBase64Key = Encoders.BASE64.encode(accessKey.getEncoded());
        System.out.println("Access Token Key: " + accessBase64Key);

        // Генерация ключа для refresh токенов
        SecretKey refreshKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS512);
        String refreshBase64Key = Encoders.BASE64.encode(refreshKey.getEncoded());
        System.out.println("Refresh Token Key: " + refreshBase64Key);

        System.out.println("\nДобавьте эти ключи в application.yml:");
        System.out.println("token:");
        System.out.println("  signing:");
        System.out.println("    key:");
        System.out.println("      access: \"" + accessBase64Key + "\"");
        System.out.println("      refresh: \"" + refreshBase64Key + "\"");
    }
}
package com.example.jwtauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Запрос на обновление токенов")
public class RefreshTokenRequest {

    @Schema(description = "Refresh токен", example = "eyJhbGciOiJIUzUxMiJ9...")
    @NotBlank(message = "Refresh токен не может быть пустым")
    private String refreshToken;
}
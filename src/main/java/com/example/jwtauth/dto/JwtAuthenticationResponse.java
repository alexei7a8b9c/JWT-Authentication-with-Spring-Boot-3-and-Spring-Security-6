package com.example.jwtauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Ответ c токенами доступа")
public class JwtAuthenticationResponse {

    @Schema(description = "Тип токена", example = "Bearer")
    private final String type = "Bearer";

    @Schema(description = "Access токен", example = "eyJhbGciOiJIUzUxMiJ9...")
    private String accessToken;

    @Schema(description = "Refresh токен", example = "eyJhbGciOiJIUzUxMiJ9...")
    private String refreshToken;

    @Schema(description = "Время жизни access токена в секундах", example = "300")
    private Long accessTokenExpiresIn;

    @Schema(description = "Время жизни refresh токена в секундах", example = "2592000")
    private Long refreshTokenExpiresIn;
}
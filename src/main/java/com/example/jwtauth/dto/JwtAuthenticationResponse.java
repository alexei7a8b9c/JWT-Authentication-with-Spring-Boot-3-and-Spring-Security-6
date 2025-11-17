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
@Schema(description = "Ответ c токеном доступа")
public class JwtAuthenticationResponse {

    @Schema(description = "Токен доступа", example = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTYxMjM5OTI4MH0.E5M6qL1sZzJ3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3J3")
    private String token;
}
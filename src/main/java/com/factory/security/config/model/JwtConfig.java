package com.factory.security.config.model;

import lombok.Data;

@Data
public class JwtConfig {
    private String jwtSecret;
    private long jwtAccessTokenExpirationInMs;
    private long jwtRefreshTokenExpirationInMs;
}

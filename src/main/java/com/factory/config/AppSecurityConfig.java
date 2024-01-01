package com.factory.config;

import lombok.Data;

@Data
public class AppSecurityConfig {
    private Boolean useKeycloak;
    private String clientId;
}


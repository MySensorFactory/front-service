package com.factory.security.config.model;

import lombok.Data;

@Data
public class LoginAttempts {
    private Integer maxAttempts;
    private Integer renewInMinutes;
}

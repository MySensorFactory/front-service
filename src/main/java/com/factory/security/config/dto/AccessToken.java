package com.factory.security.config.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AccessToken {
    private String token;
}

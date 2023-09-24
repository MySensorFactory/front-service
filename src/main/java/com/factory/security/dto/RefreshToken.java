package com.factory.security.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RefreshToken {
    private String token;
}

package com.factory.config;

import lombok.Data;

@Data
public class CreateUserConfig {
    private String toPath;
    private String fromPath;
    private String targetService;
}

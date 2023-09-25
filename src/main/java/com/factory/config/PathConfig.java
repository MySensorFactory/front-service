package com.factory.config;

import lombok.Data;

import java.util.List;

@Data
public class PathConfig {
    private List<String> publicPaths;
    private List<String> accessTokenAcquirablePaths;
    private CreateUserConfig createAccount;
}

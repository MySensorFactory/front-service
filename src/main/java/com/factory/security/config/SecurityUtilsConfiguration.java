package com.factory.security.config;

import com.factory.security.config.model.JwtConfig;
import com.factory.security.config.model.LoginAttempts;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class SecurityUtilsConfiguration {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    @ConfigurationProperties("jwt")
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }

    @Bean
    @ConfigurationProperties("login")
    public LoginAttempts loginAttempts() {
        return new LoginAttempts();
    }

    @Bean
    public LoadingCache<String, Integer> loggingAttemptsCache(final LoginAttempts loginAttempts) {
        return Caffeine.newBuilder()
                .expireAfterWrite(loginAttempts.getRenewInMinutes(), TimeUnit.MINUTES)
                .build(k -> 0);
    }
}

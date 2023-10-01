package com.factory.security.service;


import com.factory.security.config.model.LoginAttempts;
import com.github.benmanes.caffeine.cache.LoadingCache;
import lombok.RequiredArgsConstructor;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class LoginAttemptsService {
    private final LoadingCache<String, Integer> loginAttemptsCache;
    private final LoginAttempts loginAttempts;

    public boolean isMaxLoggingAttemptsCountAchieved(final ServerHttpRequest request) {
        var address = resolveAddress(request);
        var currentClientAttemptsCount = loginAttemptsCache.get(address);
        return currentClientAttemptsCount > loginAttempts.getMaxAttempts();
    }

    public void updateCurrentLoginAttemptsCount(final ServerHttpRequest request) {
        var address = resolveAddress(request);
        var currentClientAttemptsCount = loginAttemptsCache.get(address);
        loginAttemptsCache.put(address, currentClientAttemptsCount + 1);
    }


    private String resolveAddress(final ServerHttpRequest request) {
        final String xfHeader = request.getHeaders().getFirst("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0];
        }
        return Objects.requireNonNull(request.getRemoteAddress()).getHostString();
    }
}

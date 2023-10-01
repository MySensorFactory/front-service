package com.factory.security.service;

import com.factory.security.dto.AccessToken;
import com.factory.security.dto.RefreshToken;
import com.factory.security.dto.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class TokenService {

    private final JwtTokenProvider jwtTokenProvider;
    private final RemoteUserDetailsService userDetailsService;

    public Mono<RefreshToken> generateRefreshToken(final RefreshToken refreshToken) {
        return getUser(refreshToken).map(user -> {
            var token = jwtTokenProvider.generateRefreshToken(user);
            return RefreshToken.builder().token(token).build();
        });
    }

    public Mono<AccessToken> generateAccessToken(final RefreshToken refreshToken) {
        return getUser(refreshToken)
                .map(user -> {
                    var token = jwtTokenProvider.generateAccessToken(user);
                    return AccessToken.builder().token(token).build();
                });
    }

    private Mono<User> getUser(final RefreshToken refreshToken) {
        String username = jwtTokenProvider.getUsernameFromRefreshToken(refreshToken);
        return userDetailsService.loadUser(username).cast(User.class);
    }
}

package com.factory.security.service;

import com.factory.security.config.dto.AccessToken;
import com.factory.security.config.dto.RefreshToken;
import com.factory.security.config.dto.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationService {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;

    public RefreshToken generateRefreshToken(final RefreshToken refreshToken) {
        var user = getUser(refreshToken);
        var token = jwtTokenProvider.generateRefreshToken(user);
        return  RefreshToken.builder().token(token).build();
    }

    public AccessToken generateAccessToken(final RefreshToken refreshToken) {
        var user = getUser(refreshToken);
        var token = jwtTokenProvider.generateAccessToken(user);
        return  AccessToken.builder().token(token).build();
    }

    private User getUser(final RefreshToken refreshToken) {
        String username = jwtTokenProvider.getUsernameFromRefreshToken(refreshToken);
        return (User) userDetailsService.loadUserByUsername(username);
    }
}

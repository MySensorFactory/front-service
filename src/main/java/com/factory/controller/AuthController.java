package com.factory.controller;

import com.factory.security.config.dto.RefreshToken;
import com.factory.openapi.api.LoginApi;
import com.factory.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
public class AuthController {

    public static final String ACCESS_TOKEN = "Access-Token";
    public static final String REFRESH_TOKEN = "Refresh-Token";
    private final AuthenticationService authenticationService;

    //    @Override
    @PostMapping("/login")
    public Mono<ResponseEntity<Void>> login(final String authData) {
        return Mono.empty();
    }

    @Override
    public ResponseEntity<Void> refresh(final String refreshToken) {
        var accessToken = authenticationService.generateAccessToken(RefreshToken.builder().token(refreshToken).build());
        var newRefreshToken = authenticationService.generateRefreshToken(RefreshToken.builder().token(refreshToken).build());
        return ResponseEntity.ok()
                .header(ACCESS_TOKEN, accessToken.getToken())
                .header(REFRESH_TOKEN, newRefreshToken.getToken())
                .build();
    }
}


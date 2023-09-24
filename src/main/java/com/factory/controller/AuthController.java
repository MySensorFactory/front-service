package com.factory.controller;

import com.factory.security.dto.RefreshToken;
import com.factory.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import static com.factory.commons.Constants.ACCESS_TOKEN;
import static com.factory.commons.Constants.REFRESH_TOKEN;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public Mono<ResponseEntity<Void>> login(final String authData) {
        return Mono.empty();
    }

    @PostMapping("/refresh")
    public Mono<ResponseEntity<Void>> refresh(@RequestHeader(REFRESH_TOKEN) final String refreshToken) {
        var accessToken = authenticationService.generateAccessToken(RefreshToken.builder().token(refreshToken).build());
        var newRefreshToken = authenticationService.generateRefreshToken(RefreshToken.builder().token(refreshToken).build());

        return Mono.zip(accessToken, newRefreshToken)
                .map(objects -> ResponseEntity.ok()
                        .header(ACCESS_TOKEN, objects.getT1().getToken())
                        .header(REFRESH_TOKEN, objects.getT2().getToken())
                        .build());
    }
}


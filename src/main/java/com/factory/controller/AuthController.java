package com.factory.controller;

import com.factory.openapi.api.LoginApi;
import com.factory.security.dto.RefreshToken;
import com.factory.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static com.factory.commons.Constants.ACCESS_TOKEN;
import static com.factory.commons.Constants.REFRESH_TOKEN;

@RestController
@RequiredArgsConstructor
public class AuthController implements LoginApi {

    private final AuthenticationService authenticationService;

    @Override
    public Mono<ResponseEntity<Void>> login(final String authData, final ServerWebExchange exchange) {
        return Mono.empty();
    }

    @Override
    public Mono<ResponseEntity<Void>> refresh(final String refreshToken, final ServerWebExchange exchange) {
        var accessToken = authenticationService.generateAccessToken(RefreshToken.builder().token(refreshToken).build());
        var newRefreshToken = authenticationService.generateRefreshToken(RefreshToken.builder().token(refreshToken).build());

        return Mono.zip(accessToken, newRefreshToken)
                .map(objects -> ResponseEntity.ok()
                        .header(ACCESS_TOKEN, objects.getT1().getToken())
                        .header(REFRESH_TOKEN, objects.getT2().getToken())
                        .build());
    }
}


package com.factory.controller;

import com.factory.config.AppSecurityConfig;
import com.factory.exception.ServerErrorException;
import com.factory.openapi.api.LoginApi;
import com.factory.openapi.model.Error;
import com.factory.security.dto.RefreshToken;
import com.factory.security.service.AuthenticationService;
import com.factory.security.service.TokenService;
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

    private final TokenService tokenService;
    private final AuthenticationService authenticationService;
    private final AppSecurityConfig appSecurityConfig;

    @Override
    public Mono<ResponseEntity<Void>> login(final String authData, final ServerWebExchange exchange) {
        if(appSecurityConfig.getUseKeycloak()){
            return getErrorWhenKeycloakIsUsed();
        }

        return authenticationService.login(authData, exchange)
                .then(Mono.fromCallable(() -> ResponseEntity.ok().build()));
    }

    @Override
    public Mono<ResponseEntity<Void>> refresh(final String refreshToken, final ServerWebExchange exchange) {
        if(appSecurityConfig.getUseKeycloak()){
            return getErrorWhenKeycloakIsUsed();
        }

        var accessToken = tokenService.generateAccessToken(RefreshToken.builder().token(refreshToken).build());
        var newRefreshToken = tokenService.generateRefreshToken(RefreshToken.builder().token(refreshToken).build());

        return Mono.zip(accessToken, newRefreshToken)
                .map(objects -> ResponseEntity.ok()
                        .header(ACCESS_TOKEN, objects.getT1().getToken())
                        .header(REFRESH_TOKEN, objects.getT2().getToken())
                        .build());
    }

    private static Mono<ResponseEntity<Void>> getErrorWhenKeycloakIsUsed() {
        return Mono.error(() -> new ServerErrorException(Error.CodeEnum.INTERNAL_SERVER_ERROR,
                "Service unavailable when keycloak is used"));
    }
}


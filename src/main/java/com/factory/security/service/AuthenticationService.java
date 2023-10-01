package com.factory.security.service;

import com.factory.exception.ClientErrorException;
import com.factory.exception.PasswordAuthException;
import com.factory.openapi.model.Error;
import com.factory.security.dto.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;

import static com.factory.commons.Constants.ACCESS_TOKEN;
import static com.factory.commons.Constants.AUTH_DATA_DELIMITER;
import static com.factory.commons.Constants.REFRESH_TOKEN;
import static java.nio.charset.StandardCharsets.UTF_8;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final JwtTokenProvider jwtTokenProvider;
    private final RemoteUserDetailsService remoteUserDetailsService;
    private final LoginAttemptsService loginAttemptsService;

    public Mono<Void> login(final String authData, final ServerWebExchange exchange) {
        var request = exchange.getRequest();
        var response = exchange.getResponse();

        if (loginAttemptsService.isMaxLoggingAttemptsCountAchieved(request)) {
            return Mono.error(() -> new ClientErrorException(Error.CodeEnum.FORBIDDEN,
                    "Too many login attempts"));
        }

        return attemptAuthentication(authData)
                .flatMap(userDetails -> {
                            performSuccessfulAuthentication(response, (User) userDetails);
                            return Mono.empty();
                        }
                )
                .doOnError(PasswordAuthException.class,
                        e -> loginAttemptsService.updateCurrentLoginAttemptsCount(request))
                .onErrorResume(Mono::error)
                .then();
    }

    private Mono<UserDetails> attemptAuthentication(final String authDataToken)
            throws AuthenticationException {
        String[] decodedToken = decodeAuthDataToken(authDataToken);
        String username = getUsername(decodedToken);
        String password = getPassword(decodedToken);
        return remoteUserDetailsService.loadUser(username, password);
    }

    private String getPassword(final String[] decodedToken) {
        return decodedToken[1];
    }

    private String getUsername(final String[] decodedToken) {
        return decodedToken[0];
    }

    private String[] decodeAuthDataToken(final String authDataToken) {
        byte[] decodedBytes = Base64.getDecoder().decode(authDataToken);
        String decodedToken = new String(decodedBytes, UTF_8);
        return decodedToken.split(AUTH_DATA_DELIMITER);
    }

    protected void performSuccessfulAuthentication(final ServerHttpResponse response,
                                                   final User user) {
        var accessToken = jwtTokenProvider.generateAccessToken(user);
        var refreshToken = jwtTokenProvider.generateRefreshToken(user);
        response.getHeaders().set(ACCESS_TOKEN, accessToken);
        response.getHeaders().set(REFRESH_TOKEN, refreshToken);
    }
}

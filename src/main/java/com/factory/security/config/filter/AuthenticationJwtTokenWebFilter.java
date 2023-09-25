package com.factory.security.config.filter;

import com.factory.security.dto.User;
import com.factory.security.service.JwtTokenProvider;
import com.factory.security.service.RemoteUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Base64;

import static com.factory.commons.Constants.ACCESS_TOKEN;
import static com.factory.commons.Constants.AUTH_DATA;
import static com.factory.commons.Constants.AUTH_DATA_DELIMITER;
import static com.factory.commons.Constants.REFRESH_TOKEN;
import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@RequiredArgsConstructor
public class AuthenticationJwtTokenWebFilter implements WebFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RemoteUserDetailsService remoteUserDetailsService;
    private final PathConfig pathConfig;

    @Override
    public Mono<Void> filter(final ServerWebExchange exchange,final WebFilterChain chain) {
        var request = exchange.getRequest();
        var response = exchange.getResponse();

        if (!requiresAuthentication(request)) {
            return chain.filter(exchange);
        }

        return attemptAuthentication(request)
                .flatMap(userDetails -> {
                    successfulAuthentication(response, (User) userDetails);
                    return chain.filter(exchange);
                })
                .onErrorResume(Mono::error);
    }

    private boolean requiresAuthentication(final ServerHttpRequest request) {
        return pathConfig.getAccessTokenAcquirablePaths().contains(request.getPath().value());
    }

    private Mono<UserDetails> attemptAuthentication(final ServerHttpRequest request)
            throws AuthenticationException {
        String[] decodedToken = decodeAuthDataToken(request);
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

    private String[] decodeAuthDataToken(final ServerHttpRequest request) {
        var authDataToken = request.getHeaders().getFirst(AUTH_DATA);
        byte[] decodedBytes = Base64.getDecoder().decode(authDataToken);
        String decodedToken = new String(decodedBytes, UTF_8);
        return decodedToken.split(AUTH_DATA_DELIMITER);
    }

    protected void successfulAuthentication(final ServerHttpResponse response,
                                            final User user) {
        var accessToken = jwtTokenProvider.generateAccessToken(user);
        var refreshToken = jwtTokenProvider.generateRefreshToken(user);
        response.getHeaders().set(ACCESS_TOKEN, accessToken);
        response.getHeaders().set(REFRESH_TOKEN, refreshToken);
    }
}

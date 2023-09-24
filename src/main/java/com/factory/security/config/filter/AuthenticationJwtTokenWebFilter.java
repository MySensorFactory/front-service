package com.factory.security.config.filter;

import com.factory.security.config.dto.User;
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

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@RequiredArgsConstructor
public class AuthenticationJwtTokenWebFilter implements WebFilter {

    public static final String AUTH_DATA = "Auth-Data";
    public static final String AUTH_DATA_DELIMITER = ":";
    public static final String ACCESS_TOKEN = "Access-Token";
    public static final String REFRESH_TOKEN = "Refresh-Token";
    private final JwtTokenProvider jwtTokenProvider;
    private final RemoteUserDetailsService remoteUserDetailsService;

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
        return !request.getHeaders().containsKey(ACCESS_TOKEN);
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
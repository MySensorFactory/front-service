package com.factory.security.config.filter;

import com.factory.config.PathConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Slf4j
@Order(1)
@RequiredArgsConstructor
public class ProcessingJwtTokenWebFilter implements WebFilter {

    public static final String ACCESS_TOKEN = "Access-Token";

    private final ReactiveAuthenticationManager authenticationManager;
    private final PathConfig pathConfig;

    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final WebFilterChain chain) {
        if (isPublicEndpoint(exchange.getRequest().getPath().toString())) {
            return chain.filter(exchange);
        }

        String accessToken = exchange.getRequest().getHeaders().getFirst(ACCESS_TOKEN);
        var authority = new UsernamePasswordAuthenticationToken(null, accessToken, null);
        if (isTokenProvided(accessToken)) {
            return authenticationManager.authenticate(authority)
                    .flatMap(authToken -> {
                        setAuthentication(authToken);
                        return chain.filter(exchange);
                    });
        }

        return chain.filter(exchange);
    }

    private boolean isTokenProvided(final String accessToken) {
        return Objects.nonNull(accessToken);
    }

    private boolean isPublicEndpoint(final String path) {
        return pathConfig.getPublicPaths().contains(path);
    }

    private void setAuthentication(final Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}

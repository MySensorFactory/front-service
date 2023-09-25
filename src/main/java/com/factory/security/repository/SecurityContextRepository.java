package com.factory.security.repository;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static com.factory.commons.Constants.ACCESS_TOKEN;

@AllArgsConstructor
@Slf4j
@Component
public class SecurityContextRepository implements ServerSecurityContextRepository {
    private ReactiveAuthenticationManager authenticationManager;

    @Override
    public Mono<Void> save(final ServerWebExchange swe, final SecurityContext sc) {
        log.error("Called unsupported SecurityContextRepository.save() method");
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Mono<SecurityContext> load(final ServerWebExchange swe) {
        return Mono.justOrEmpty(swe.getRequest().getHeaders().getFirst(ACCESS_TOKEN))
                .flatMap(authHeader -> {
                    Authentication auth = new UsernamePasswordAuthenticationToken(null, authHeader);
                    return this.authenticationManager.authenticate(auth).map(SecurityContextImpl::new);
                });
    }
}

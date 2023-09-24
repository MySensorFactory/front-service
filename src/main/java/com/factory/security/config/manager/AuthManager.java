package com.factory.security.config.manager;

import com.factory.security.config.dto.AccessToken;
import com.factory.security.service.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class AuthManager implements ReactiveAuthenticationManager {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication.getCredentials().toString())
                .flatMap(accessToken -> {
                    var user = jwtTokenProvider.parseAccessToken(AccessToken.builder().token(accessToken).build());
                    var authorities = user.getRoles().stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();
                    return Mono.just(new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities));
                });
    }
}

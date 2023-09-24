package com.factory.security.config;

import com.factory.config.ApiGatewayConfiguration;
import com.factory.security.config.filter.AuthenticationJwtTokenWebFilter;
import com.factory.security.config.filter.ProcessingJwtTokenWebFilter;
import com.factory.security.repository.SecurityContextRepository;
import com.factory.security.service.JwtTokenProvider;
import com.factory.security.service.RemoteUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtTokenProvider jwtTokenProvider;
    private final ReactiveAuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final RemoteUserDetailsService remoteUserDetailsService;
    private final ApiGatewayConfiguration apiGatewayConfiguration;

    // @formatter:off
    @Bean
    public SecurityWebFilterChain securitygWebFilterChain(final ServerHttpSecurity http) {
        return http
                .csrf().disable()
                .exceptionHandling()
                    .authenticationEntryPoint((swe, e) ->
                            Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED))
                    ).accessDeniedHandler((swe, e) ->
                            Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN))
                ).and()
                .formLogin().disable()
                .httpBasic().disable()
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                    .pathMatchers(HttpMethod.OPTIONS).permitAll()
                    .pathMatchers("/login").permitAll()
                    .pathMatchers("/login/**").permitAll()
                    .pathMatchers("/refresh").permitAll()
                    .pathMatchers("/refresh/**").permitAll()
                    .pathMatchers("/v3/**").permitAll()
//                    .pathMatchers("/counted-words").hasRole("DATA_ACCESSOR")
//                    .pathMatchers("/counted-words/**").hasRole("DATA_ACCESSOR")
                    .anyExchange().authenticated()
                .and()
                .addFilterAt(new AuthenticationJwtTokenWebFilter(jwtTokenProvider, remoteUserDetailsService),
                        SecurityWebFiltersOrder.AUTHENTICATION)
                .addFilterBefore(new ProcessingJwtTokenWebFilter(authenticationManager, apiGatewayConfiguration.pathConfig()),
                        SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
    // @formatter:on
}

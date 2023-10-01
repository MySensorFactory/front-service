package com.factory.security.config;

import com.factory.config.ApiGatewayConfiguration;
import com.factory.config.PathConfig;
import com.factory.security.filter.AuthenticationJwtTokenWebFilter;
import com.factory.security.filter.ProcessingJwtTokenWebFilter;
import com.factory.security.repository.SecurityContextRepository;
import com.factory.security.service.JwtTokenProvider;
import com.factory.security.service.LoginAttemptsService;
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

    public static final String ADMIN = "ADMIN";
    public static final String DATA_ACCESSOR = "DATA_ACCESSOR";
    private final JwtTokenProvider jwtTokenProvider;
    private final ReactiveAuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final RemoteUserDetailsService remoteUserDetailsService;
    private final ApiGatewayConfiguration apiGatewayConfiguration;
    private final PathConfig pathConfig;
    private final LoginAttemptsService loginAttemptsService;

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
                    .pathMatchers(pathConfig.getPublicPaths().toArray(new String[0])).permitAll()

                    .pathMatchers("/data/**").hasRole(DATA_ACCESSOR)

                    .pathMatchers(HttpMethod.GET,"/users/{userName}").authenticated()
                    .pathMatchers(HttpMethod.PATCH, "/users/{userName}").hasRole(ADMIN)
                    .pathMatchers(HttpMethod.POST, "/users/{userName}/activate").hasRole(ADMIN)

                    .pathMatchers("/roles/**").hasRole(ADMIN)

                    .anyExchange().authenticated()
                .and()
                .addFilterAt(new AuthenticationJwtTokenWebFilter(
                                jwtTokenProvider,
                                remoteUserDetailsService,
                                pathConfig,
                                loginAttemptsService),
                        SecurityWebFiltersOrder.AUTHENTICATION)
                .addFilterBefore(new ProcessingJwtTokenWebFilter(authenticationManager, apiGatewayConfiguration.pathConfig()),
                        SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
    // @formatter:on
}

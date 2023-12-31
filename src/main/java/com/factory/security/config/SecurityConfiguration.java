package com.factory.security.config;

import com.factory.config.ApiGatewayConfiguration;
import com.factory.config.PathConfig;
import com.factory.security.filter.ProcessingJwtTokenWebFilter;
import com.factory.security.repository.SecurityContextRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    public static final String ADMIN = "ADMIN";
    public static final String DATA_ACCESSOR = "DATA_ACCESSOR";
    private final ReactiveAuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final ApiGatewayConfiguration apiGatewayConfiguration;
    private final PathConfig pathConfig;

    // @formatter:off
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(final ServerHttpSecurity http,
                                                         final Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter) {
        http
                .csrf().disable()
                .exceptionHandling()
                    .authenticationEntryPoint((swe, e) ->
                            Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED))
                    ).accessDeniedHandler((swe, e) ->
                            Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN))
                )
                .and()
                .formLogin().disable()
                .httpBasic().disable();

        if (apiGatewayConfiguration.appSecurityConfig().getUseKeycloak()){
            http
                    .oauth2ResourceServer()
                    .jwt()
                    .jwtAuthenticationConverter(jwtAuthenticationConverter);
        }
        else {
            http
                    .authenticationManager(authenticationManager)
                    .securityContextRepository(securityContextRepository)
                    .addFilterBefore(new ProcessingJwtTokenWebFilter(authenticationManager, pathConfig),
                            SecurityWebFiltersOrder.AUTHENTICATION);
        }

        http
                .authorizeExchange()
                    .pathMatchers(HttpMethod.OPTIONS).permitAll()
                    .pathMatchers(pathConfig.getPublicPaths().toArray(new String[0])).permitAll()

                    .pathMatchers("/data/**").hasRole(DATA_ACCESSOR)

                    .pathMatchers(HttpMethod.GET,"/users/users/{userName}").authenticated()
                    .pathMatchers(HttpMethod.PATCH, "/users/users/{userName}").hasRole(ADMIN)
                    .pathMatchers(HttpMethod.POST, "/users/users/{userName}/activate").hasRole(ADMIN)

                    .pathMatchers("/roles/**").hasRole(ADMIN)

                    .anyExchange().authenticated();

                return http.build();
    }
    // @formatter:on
}

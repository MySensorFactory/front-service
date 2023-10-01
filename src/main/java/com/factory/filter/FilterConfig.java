package com.factory.filter;

import com.factory.config.PathConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@ConditionalOnProperty(
        value = "config.createAccount.enabled",
        havingValue = "true"
)
@RequiredArgsConstructor
public class FilterConfig {

    public static final String FILTER_ID = "path_route_change";
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final PasswordEncoder passwordEncoder;
    private final PathConfig pathConfig;

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        return builder
                .routes()
                .route(FILTER_ID,
                        r -> r.path(pathConfig.getCreateAccount().getFromPath())
                                .filters(f -> f
                                        .rewritePath(pathConfig.getCreateAccount().getFromPath(),
                                                pathConfig.getCreateAccount().getToPath())
                                        .modifyRequestBody(String.class, String.class,
                                                new CreateUserRequestRolesFilter(objectMapper))
                                        .modifyRequestBody(String.class, String.class,
                                                new CreateUserRequestBodyPasswordEncodeFilter(objectMapper, passwordEncoder))
                                )
                                .uri(pathConfig.getCreateAccount().getTargetService()))
                .build();
    }
}

package com.factory.filter;

import com.factory.exception.ClientErrorException;
import com.factory.openapi.model.CreateUserRequest;
import com.factory.openapi.model.Error;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicBoolean;


@Slf4j
@RequiredArgsConstructor
public class CreateUserRequestRolesFilter implements RewriteFunction<String, String> {

    public static final String ADMIN = "ADMIN";
    private final ObjectMapper objectMapper;

    @Override
    public Publisher<String> apply(final ServerWebExchange exchange, final String body) {
        try {
            var request = objectMapper.readValue(body, CreateUserRequest.class);
            if (isRequestContainAdminRole(request)) {
                return Mono.error(() -> new ClientErrorException(Error.CodeEnum.INVALID_INPUT, "Cannot create ADMIN-like users"));
            }
            return Mono.just(objectMapper.writeValueAsString(request));
        } catch (final Exception ex) {
            log.error("Error during serialization/deserialization: Details: {}", ex.getMessage());
            return Mono.error(ex);
        }
    }

    private boolean isRequestContainAdminRole(final CreateUserRequest request) {
        final AtomicBoolean result = new AtomicBoolean(false);
        request.getRoles().forEach(r -> {
            if (r.getName().toUpperCase().contains(ADMIN)) {
                result.set(true);
            }
        });
        return result.get();
    }
}
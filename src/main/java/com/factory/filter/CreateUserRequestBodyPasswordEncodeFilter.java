package com.factory.filter;

import com.factory.openapi.model.CreateUserRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Slf4j
@RequiredArgsConstructor
public class CreateUserRequestBodyPasswordEncodeFilter implements RewriteFunction<String, String> {

    private final ObjectMapper objectMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Publisher<String> apply(final ServerWebExchange exchange, final String body) {
        try {
            return getBodyWithEncodedPassword(body);
        } catch (final Exception ex) {
            log.error("Error during password encoding: Details: {}", ex.getMessage());
            return Mono.error(ex);
        }
    }

    private Mono<String> getBodyWithEncodedPassword(final String body) throws JsonProcessingException {
        var request = objectMapper.readValue(body, CreateUserRequest.class);
        request.setPassword(passwordEncoder.encode(request.getPassword()));
        return Mono.just(objectMapper.writeValueAsString(request));
    }
}
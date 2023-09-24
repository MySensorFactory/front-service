package com.factory.controller;

import com.factory.exception.ClientErrorException;
import com.factory.exception.ServerErrorException;
import com.factory.openapi.model.Error;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@Slf4j
@Order(-2)
public class ReactiveExceptionHandler extends AbstractErrorWebExceptionHandler {

    Map<Class<? extends Throwable>, Function<Throwable, Mono<ServerResponse>>> exceptionHandlers = new HashMap<>();

    public ReactiveExceptionHandler(final ErrorAttributes errorAttributes,
                                    final WebProperties.Resources resources,
                                    final ApplicationContext applicationContext,
                                    ServerCodecConfigurer serverCodecConfigurer) {
        super(errorAttributes, resources, applicationContext);
        super.setMessageWriters(serverCodecConfigurer.getWriters());
        super.setMessageReaders(serverCodecConfigurer.getReaders());

        exceptionHandlers.put(ExpiredJwtException.class, exception -> this.handle((ExpiredJwtException) exception));
        exceptionHandlers.put(ClientErrorException.class, exception -> this.handle((ClientErrorException) exception));
        exceptionHandlers.put(ServerErrorException.class, exception -> this.handle((ServerErrorException) exception));
        exceptionHandlers.put(AuthenticationException.class, exception -> this.handle((AuthenticationException) exception));
        exceptionHandlers.put(AuthorizationServiceException.class, exception -> this.handle((AuthorizationServiceException) exception));
        exceptionHandlers.put(UnsupportedJwtException.class, exception -> this.handle((UnsupportedJwtException) exception));
        exceptionHandlers.put(MalformedJwtException.class, exception -> this.handle((MalformedJwtException) exception));
    }

    @Override
    protected RouterFunction<ServerResponse> getRoutingFunction(final ErrorAttributes errorAttributes) {
        return RouterFunctions.route(
                RequestPredicates.all(), this::renderErrorResponse);
    }

    private Mono<ServerResponse> renderErrorResponse(final ServerRequest request) {
        var throwable = getError(request);
        return exceptionHandlers.entrySet().stream()
                .filter(entry -> entry.getKey().isInstance(throwable))
                .findFirst()
                .map(entry -> entry.getValue().apply(throwable))
                .orElseGet(() -> handleGenericError(throwable));
    }

    public Mono<ServerResponse> handle(final ExpiredJwtException ex) {
        log.warn("Token expired");
        var error = getError(ex);
        return ServerResponse.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(error));
    }

    public Mono<ServerResponse> handle(final ClientErrorException ex) {
        var error = getError(ex);
        return ServerResponse.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(error));
    }

    public Mono<ServerResponse> handle(final ServerErrorException ex) {
        var error = getError(ex);
        return ServerResponse.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(error));
    }

    public Mono<ServerResponse> handle(final AuthenticationException ex) {
        var error = getError(ex);
        return ServerResponse.status(HttpStatus.UNAUTHORIZED)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(error));
    }

    public Mono<ServerResponse> handle(final AuthorizationServiceException ex) {
        var error = getError(ex);
        return ServerResponse.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(error));
    }

    public Mono<ServerResponse> handle(final UnsupportedJwtException ex) {
        log.warn("Bad JWT token format");
        var error = getError(ex);
        return ServerResponse.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(error));
    }

    public Mono<ServerResponse> handle(final MalformedJwtException ex) {
        log.warn("JWT token is malformed");
        var error = getError(ex);
        return ServerResponse.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(error));
    }

    public Mono<ServerResponse> handleGenericError(final Throwable throwable) {
        var error = getError(throwable);
        return ServerResponse.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(error));
    }

    private Error getError(final UnsupportedJwtException ex) {
        return Error.builder()
                .code(Error.CodeEnum.UNAUTHORIZED)
                .description("Bad JWT token format. Details: " + ex.getMessage())
                .build();
    }

    private Error getError(final MalformedJwtException ex) {
        return Error.builder()
                .code(Error.CodeEnum.UNAUTHORIZED)
                .description("JWT token is malformed. Details: " + ex.getMessage())
                .build();
    }

    private Error getError(final ExpiredJwtException ex) {
        return Error.builder()
                .code(Error.CodeEnum.UNAUTHORIZED)
                .description("Access token expired. Details: " + ex.getMessage())
                .build();
    }

    private Error getError(final AuthorizationServiceException ex) {
        return Error.builder()
                .code(Error.CodeEnum.FORBIDDEN)
                .description(ex.getMessage())
                .build();
    }

    private Error getError(final ServerErrorException ex) {
        return Error.builder()
                .code(Error.CodeEnum.fromValue(ex.getCode()))
                .description(ex.getMessage())
                .build();
    }

    private Error getError(final AuthenticationException ex) {
        return Error.builder()
                .code(Error.CodeEnum.UNAUTHORIZED)
                .description(ex.getMessage())
                .build();
    }

    private Error getError(final ClientErrorException ex) {
        return Error.builder()
                .code(Error.CodeEnum.fromValue(ex.getCode()))
                .description(ex.getMessage())
                .build();
    }

    private Error getError(final Throwable throwable) {
        return Error.builder()
                .code(Error.CodeEnum.INTERNAL_SERVER_ERROR)
                .description(throwable.getMessage())
                .build();
    }
}

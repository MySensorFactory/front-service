package com.factory.controller;

import com.factory.exception.ClientErrorException;
import com.factory.exception.ServerErrorException;
import com.factory.openapi.model.Error;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@Slf4j
public class ControllerExceptionHandler {
    @ExceptionHandler(ClientErrorException.class)
    public ResponseEntity<Error> handleClientError(final ClientErrorException ex) {
        var error = getError(ex);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    @ExceptionHandler(ServerErrorException.class)
    public ResponseEntity<Error> handleServerError(final ServerErrorException ex) {
        var error = getError(ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Error> handleServerError(final AuthenticationException ex) {
        var error = getError(ex);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(AuthorizationServiceException.class)
    public ResponseEntity<Error> handleServerError(final AuthorizationServiceException ex) {
        var error = getError(ex);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<Error> handleServerError(final ExpiredJwtException ex) {
        log.warn("Token expired");
        var error = getError(ex);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(UnsupportedJwtException.class)
    public ResponseEntity<Error> handleServerError(final UnsupportedJwtException ex) {
        log.warn("Bad JWT token format");
        var error = getError(ex);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<Error> handleServerError(final MalformedJwtException ex) {
        log.warn("JWT token is malformed");
        var error = getError(ex);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    private Error getError(final UnsupportedJwtException ex) {
        return Error.builder()
                .code(Error.CodeEnum.UNAUTHORIZED)
                .description("Bad JWT token format")
                .build();
    }

    private Error getError(final MalformedJwtException ex) {
        return Error.builder()
                .code(Error.CodeEnum.UNAUTHORIZED)
                .description("JWT token is malformed")
                .build();
    }

    private Error getError(final ExpiredJwtException ex) {
        return Error.builder()
                .code(Error.CodeEnum.UNAUTHORIZED)
                .description("Access token expired")
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

}

package com.factory.exception;

import org.springframework.security.core.AuthenticationException;

public class PasswordAuthException extends AuthenticationException {
    public PasswordAuthException(final String username) {
        super(String.format("Bad password for the user : %s", username));
    }
}

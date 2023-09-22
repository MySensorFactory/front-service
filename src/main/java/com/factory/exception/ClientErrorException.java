package com.factory.exception;

import com.factory.openapi.model.Error;
import lombok.Getter;

@Getter
public class ClientErrorException extends RuntimeException {
    private final String code;

    public ClientErrorException(final Error.CodeEnum code, final String message) {
        super(message);
        this.code = code.toString();
    }
}

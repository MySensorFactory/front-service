package com.factory.exception;

import com.factory.openapi.model.Error;
import lombok.Getter;

@Getter
public class ServerErrorException extends RuntimeException {
    private final String code;

    public ServerErrorException(final Error.CodeEnum code, final String message) {
        super(message);
        this.code = code.toString();
    }
}

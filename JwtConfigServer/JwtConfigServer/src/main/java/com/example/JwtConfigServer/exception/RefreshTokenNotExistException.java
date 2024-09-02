package com.example.JwtConfigServer.exception;

import lombok.Getter;

@Getter
public class RefreshTokenNotExistException extends RuntimeException{

    private final ErrorCode errorCode;

    public RefreshTokenNotExistException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}

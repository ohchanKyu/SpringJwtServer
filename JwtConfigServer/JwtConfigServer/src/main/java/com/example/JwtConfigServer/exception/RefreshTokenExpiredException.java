package com.example.JwtConfigServer.exception;

import lombok.Getter;

@Getter
public class RefreshTokenExpiredException extends RuntimeException{
    private final ErrorCode errorCode;

    public RefreshTokenExpiredException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}

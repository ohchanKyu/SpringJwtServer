package com.example.JwtConfigServer.exception;

import lombok.Getter;

@Getter
public class RefreshTokenNotEqualsException extends RuntimeException{

    private final ErrorCode errorCode;

    public RefreshTokenNotEqualsException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}

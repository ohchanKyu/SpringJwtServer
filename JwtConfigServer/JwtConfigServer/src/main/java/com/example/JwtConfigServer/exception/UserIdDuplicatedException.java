package com.example.JwtConfigServer.exception;

import lombok.Getter;

@Getter
public class UserIdDuplicatedException extends RuntimeException{

    private final ErrorCode errorCode;

    public UserIdDuplicatedException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}
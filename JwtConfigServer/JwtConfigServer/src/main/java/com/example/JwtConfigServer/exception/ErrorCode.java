package com.example.JwtConfigServer.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED,"Jwt Token Is Expired"),
    TOKEN_INVALID(HttpStatus.UNAUTHORIZED,"Jwt Token Is Invalid"),
    TOKEN_UNAUTHORIZED(HttpStatus.UNAUTHORIZED,"Jwt Token is Not Exists"),
    ACCESS_FORBIDDEN(HttpStatus.FORBIDDEN,"Forbidden Access This Api"),
    REFRESH_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED,"Jwt Refresh Token Expired"),
    REFRESH_TOKEN_IS_NOT_EXIST_REDIS(HttpStatus.UNAUTHORIZED,"Jwt Refresh Token Is Not Exist Redis DB"),
    REFRESH_TOKEN_IS_NOT_EQUALS_REDIS(HttpStatus.UNAUTHORIZED,"Jwt Refresh Token Is Not Equals Redis DB");

    private final HttpStatus httpStatus;
    private final String message;
}


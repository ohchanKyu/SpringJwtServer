package com.example.JwtConfigServer.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {


    @ExceptionHandler(RefreshTokenExpiredException.class)
    protected ResponseEntity<ErrorResponse> handleRefreshTokenExpiredException(RefreshTokenExpiredException ex) {
        ErrorCode errorCode = ex.getErrorCode();
        return handleExceptionInternal(errorCode);
    }
    @ExceptionHandler(RefreshTokenNotExistException.class)
    protected ResponseEntity<ErrorResponse> handleRefreshTokenNotExistException(RefreshTokenNotExistException ex) {
        ErrorCode errorCode = ex.getErrorCode();
        return handleExceptionInternal(errorCode);
    }
    @ExceptionHandler(RefreshTokenNotEqualsException.class)
    protected ResponseEntity<ErrorResponse> handleRefreshTokenNotEqualsException(RefreshTokenNotEqualsException ex) {
        ErrorCode errorCode = ex.getErrorCode();
        return handleExceptionInternal(errorCode);
    }
    private ResponseEntity<ErrorResponse> handleExceptionInternal(ErrorCode errorCode){
        return ResponseEntity
                .status(errorCode.getHttpStatus().value())
                .body(new ErrorResponse(errorCode));
    }
}

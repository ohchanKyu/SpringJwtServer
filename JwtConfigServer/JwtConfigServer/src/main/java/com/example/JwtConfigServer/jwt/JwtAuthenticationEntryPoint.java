package com.example.JwtConfigServer.jwt;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.example.JwtConfigServer.exception.ErrorCode;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import java.io.IOException;


@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final JwtSendErrorService jwtSendErrorService;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        JWTVerificationException jwtVerificationException =
                (JWTVerificationException) request.getAttribute("exception");

        // 토큰 만료의 경우 다른 응답
        if (jwtVerificationException instanceof TokenExpiredException) {
            jwtSendErrorService.sendErrorResponseProcess(response, ErrorCode.TOKEN_EXPIRED, 499);
            return;
        }
        // 유효한 토큰이 아닌 경우 다른 응답
        if (jwtVerificationException != null) {
            jwtSendErrorService.sendErrorResponseProcess(response, ErrorCode.TOKEN_INVALID, HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        // 토큰이 존재 하지 않는 경우 다른 응답
        jwtSendErrorService.sendErrorResponseProcess(response, ErrorCode.TOKEN_UNAUTHORIZED, HttpServletResponse.SC_UNAUTHORIZED);
    }

}

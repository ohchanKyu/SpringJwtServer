package com.example.JwtConfigServer.jwt;

import com.example.JwtConfigServer.exception.ErrorCode;
import com.example.JwtConfigServer.exception.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
public class JwtSendErrorService {

    private final ObjectMapper objectMapper;

    public void sendErrorResponseProcess(
            HttpServletResponse response, ErrorCode errorCode, int status)
            throws IOException {
        ErrorResponse errorResponse = new ErrorResponse(errorCode);
        String body = objectMapper.writeValueAsString(errorResponse);
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(body);
    }
}

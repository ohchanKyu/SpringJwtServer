package com.example.JwtConfigServer.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignupResponse {

    private String successMessage;
    private String accessToken;
    private String refreshToken;
}

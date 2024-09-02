package com.example.JwtConfigServer.controller;

import com.example.JwtConfigServer.dto.request.SignInRequest;
import com.example.JwtConfigServer.dto.request.SignupRequest;
import com.example.JwtConfigServer.dto.request.TokenRequest;
import com.example.JwtConfigServer.dto.response.SignupResponse;
import com.example.JwtConfigServer.dto.response.TokenResponse;
import com.example.JwtConfigServer.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/sign-up")
    public ResponseEntity<SignupResponse> signup(@RequestBody SignupRequest signupRequest){
        return ResponseEntity.ok(authService.signupProcess(signupRequest));
    }
    @PostMapping("/sign-in")
    public ResponseEntity<TokenResponse> signIn(@RequestBody SignInRequest signInRequest){
        return ResponseEntity.ok(authService.signInProcess(signInRequest));
    }
    @PostMapping("/reissue")
    public ResponseEntity<TokenResponse> reissue(@RequestBody TokenRequest tokenRequest){
        return ResponseEntity.ok(authService.reissueTokenProcess(tokenRequest));
    }
}

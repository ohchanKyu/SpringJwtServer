package com.example.JwtConfigServer.controller;

import com.example.JwtConfigServer.config.principal.PrincipalDetails;
import com.example.JwtConfigServer.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Slf4j
public class ApiController {

    private final AuthService authService;

    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails userDetails){
        log.info(userDetails.getUsername());
        return "user";
    }
    @GetMapping("/manager")
    public String manager(@AuthenticationPrincipal PrincipalDetails userDetails){
        log.info(userDetails.getUsername());
        return "manager";
    }
    @GetMapping("/admin")
    public String admin(@AuthenticationPrincipal PrincipalDetails userDetails){
        log.info(userDetails.getUsername());
        return "admin";
    }
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@AuthenticationPrincipal PrincipalDetails userDetails){
        if (authService.logoutProcess(userDetails)){
            return ResponseEntity.ok("Logout Successful");
        }else{
            return ResponseEntity.ok("Logout Fail");
        }
    }
}

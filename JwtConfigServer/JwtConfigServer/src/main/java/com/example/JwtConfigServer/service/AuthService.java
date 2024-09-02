package com.example.JwtConfigServer.service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.JwtConfigServer.config.principal.PrincipalDetails;
import com.example.JwtConfigServer.dto.request.SignInRequest;
import com.example.JwtConfigServer.dto.request.SignupRequest;
import com.example.JwtConfigServer.dto.request.TokenRequest;
import com.example.JwtConfigServer.dto.response.SignupResponse;
import com.example.JwtConfigServer.dto.response.TokenResponse;
import com.example.JwtConfigServer.entity.Member;
import com.example.JwtConfigServer.exception.ErrorCode;
import com.example.JwtConfigServer.exception.RefreshTokenExpiredException;
import com.example.JwtConfigServer.exception.RefreshTokenNotEqualsException;
import com.example.JwtConfigServer.exception.RefreshTokenNotExistException;
import com.example.JwtConfigServer.jwt.JwtRedisService;
import com.example.JwtConfigServer.jwt.JwtTokenProvider;
import com.example.JwtConfigServer.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtRedisService jwtRedisService;

    @Transactional
    public SignupResponse signupProcess(SignupRequest signupRequest) {

        String encodePassword = passwordEncoder.encode(signupRequest.getPassword());
        Member newMember = Member.builder()
                .email(signupRequest.getEmail())
                .name(signupRequest.getName())
                .password(encodePassword)
                .userId(signupRequest.getUserId())
                .roles("ROLE_USER")
                .build();
        memberRepository.save(newMember);
        return new SignupResponse("Success","","");
    }

    @Transactional
    public TokenResponse signInProcess(SignInRequest signInRequest) {

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(signInRequest.getUserId(),signInRequest.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        // 만약 로그인 실패 시 해당 로직은 실행되지 않음.
        TokenResponse token = jwtTokenProvider.generateToken(authentication);
        String userId = signInRequest.getUserId();
        jwtRedisService.saveToken(userId,token.getRefreshToken());
        return token;
    }

    public TokenResponse reissueTokenProcess(TokenRequest tokenRequest){

        String targetRefreshToken = tokenRequest.getRefreshToken();

        Authentication authentication;
        try {
            authentication = jwtTokenProvider.validateToken(targetRefreshToken);
            log.info("Verification RefreshToken - {}",targetRefreshToken);
        } catch (JWTVerificationException e){
            // 기간 만료 혹은 잘못된 JWT 토큰일 경우
            log.info("Not Valid Refresh Token -{}",targetRefreshToken);
            throw new RefreshTokenExpiredException(ErrorCode.REFRESH_TOKEN_EXPIRED);
        }
        String targetUserId = jwtTokenProvider.getUserIdFromToken(tokenRequest.getRefreshToken());
        Optional<String> redisRefreshToken = jwtRedisService.findByUserId(targetUserId);
        if (redisRefreshToken.isEmpty()){
            // 이미 로그아웃해서 DB에 없는 경우
            log.info("Not Exists Refresh Token In Redis DB -{} -{}",targetUserId,targetRefreshToken);
            throw new RefreshTokenNotExistException(ErrorCode.REFRESH_TOKEN_IS_NOT_EXIST_REDIS);
        }else{
            if (!targetRefreshToken.equals(redisRefreshToken.get())){
                // DB에 존재하지 않는 Refresh Token 이랑 일치하지 않으므로 에러 응답
                // 다시 로그인 요청
                log.info("Not Equals Refresh Token In Redis DB -{} -{}",targetUserId,targetRefreshToken);
                throw new RefreshTokenNotEqualsException(ErrorCode.REFRESH_TOKEN_IS_NOT_EQUALS_REDIS);
            }
        }
        TokenResponse newTokenDto = jwtTokenProvider.generateToken(authentication);
        log.info("New Refresh Token -{} -{}",targetUserId,newTokenDto.getRefreshToken());
        jwtRedisService.saveToken(targetUserId,newTokenDto.getRefreshToken());
        return newTokenDto;
    }

    public boolean logoutProcess(PrincipalDetails userDetails){
        String userId = userDetails.getUsername();
        Optional<String> redisRefreshToken = jwtRedisService.findByUserId(userId);
        if (redisRefreshToken.isPresent()){
            log.info("Logout User. User Id -{}",userId);
            jwtRedisService.deleteToken(userId);
        }else{
            log.info("Already Logout User. User Id -{}",userId);
            return false;
        }
        return true;
    }
}

package com.example.JwtConfigServer.jwt;

import com.example.JwtConfigServer.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static com.example.JwtConfigServer.jwt.JwtTokenProvider.REFRESH_TOKEN_EXPIRE_TIME;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtRedisService implements RefreshTokenRepository {

    private final RedisTemplate<String,String> redisTemplate;

    @Override
    public void save(String userId,String refreshToken){
        ValueOperations<String, String> operations = redisTemplate.opsForValue();

        if(!Objects.isNull(operations.get(userId))){
            log.info("Update RefreshToken. User Id - {} Delete Token - {}",userId,operations.get(userId));
            delete(userId);
        }
        operations.set(userId,refreshToken,REFRESH_TOKEN_EXPIRE_TIME, TimeUnit.SECONDS);
        log.info("Save Refresh Token. User Id - {} Save Token - {} ",userId,refreshToken);
    }

    @Override
    public Optional<String> findByUserId(String userId){
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        String refreshToken = valueOperations.get(userId);
        if(refreshToken== null){
            return Optional.empty();
        }
        else{
            return Optional.of(refreshToken);
        }
    }
    @Override
    public void delete(String userId){
        redisTemplate.delete(userId);
    }
}

package com.example.JwtConfigServer.repository;

import java.util.Optional;

public interface RefreshTokenRepository {
    void save(String userId,String refreshToken);
    Optional<String> findByUserId(String userId);
    void delete(String userId);
}
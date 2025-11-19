package com.saumik.loginModule.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String PREFIX = "refresh:";

    public void store(String username, String refreshToken, long expirationSeconds) {
        redisTemplate.opsForValue().set(
                PREFIX + username,
                refreshToken,
                expirationSeconds,
                TimeUnit.SECONDS
        );
    }

    public String get(String username) {
        return redisTemplate.opsForValue().get(PREFIX + username);
    }

    public void delete(String username) {
        redisTemplate.delete(PREFIX + username);
    }
}

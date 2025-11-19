package com.saumik.loginModule.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class AuthUtil {

    @Value("${jwt.secretKey}")
    private String jwtSecretKey;

    @Value("${jwt.expirationMs}")
    private long expirationMs;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpirationMs;

    private static final String REFRESH = "refresh";
    private static final String ROLES = "roles";

    // -------------------
    // Token generation
    // -------------------

    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication, new HashMap<>(), expirationMs);
    }

    public String generateRefreshToken(Authentication authentication) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("tokenType", REFRESH);
        return generateToken(authentication, claims, refreshExpirationMs);
    }

    private String generateToken(Authentication authentication, Map<String, Object> claims,long expirationMs) {

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        claims.put(ROLES, roles);

        Date now = new Date();
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claims(claims)
                .issuedAt(now)
                .expiration(new Date(now.getTime()+expirationMs))
                .signWith(getSecretKey(),Jwts.SIG.HS256)
                .compact();

    }


    // -------------------
    // Token validation
    // -------------------

    public boolean validateToken(String token) {
        try {
            Claims claims = extractClaims(token);
            return claims.getExpiration().after(new Date());
        } catch (ExpiredJwtException e) {
            log.error("Token expired: {}", e.getMessage());
        } catch (JwtException e) {
            log.error("Token invalid: {}", e.getMessage());
        }
        return false;
    }

    public boolean isRefreshToken(String token) {
        try {
            Claims claims = extractClaims(token);
            return REFRESH.equals(claims.get("tokenType"));
        } catch (Exception e) {
            return false;
        }
    }

    // -------------------
    // Claims extraction
    // -------------------

    // extract claims
    public Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getUsernameFromToken(String token) {
        return extractClaims(token).getSubject();
    }

    public List<? extends GrantedAuthority> extractRoles(String token) {
        Claims claims = extractClaims(token);

        List<?> roles = claims.get("roles", List.class);
        if (roles == null) return List.of();

        return roles.stream()
                .map(Object::toString)
                .map(SimpleGrantedAuthority::new)
                .toList();
    }



    // -------------------
    // Secret key helper
    // -------------------

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey));
    }
}





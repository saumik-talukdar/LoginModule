package com.saumik.loginModule.service;

import com.saumik.loginModule.dto.*;
import com.saumik.loginModule.entity.User;
import com.saumik.loginModule.repository.UserRepository;
import com.saumik.loginModule.security.AuthUtil;
import com.saumik.loginModule.security.CustomUserDetailsService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final AuthUtil authUtil;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsService userDetailsService;
    private final CustomUserDetailsService customUserDetailsService;

    public JwtTokenResponse login(@Valid LoginRequestDto req) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );

        User user = (User) authentication.getPrincipal();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = authUtil.generateAccessToken(authentication);
        String refreshToken = authUtil.generateRefreshToken(authentication);

        // Store refresh token in Redis
        refreshTokenService.store(
                user.getUsername(),
                refreshToken,
                10 * 24 * 3600
        );

        return new JwtTokenResponse(accessToken, refreshToken, null);
    }


    public JwtTokenResponse register(@Valid SignupRequestDto req) {
        if (userRepository.findByUsername(req.getUsername()).isPresent()) {
            return new JwtTokenResponse(null,null,"Username is already taken");
        }
        if (userRepository.findByEmail(req.getEmail()).isPresent()) {
            return new JwtTokenResponse(null,null,"Email already exists");
        }

        User user = new User();
        user.setUsername(req.getUsername());
        user.setEmail(req.getEmail());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setRoles(List.of("ROLE_USER"));
        userRepository.save(user);
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = authUtil.generateAccessToken(authentication);
        String refreshToken = authUtil.generateRefreshToken(authentication);

        refreshTokenService.store(
                user.getUsername(),
                refreshToken,
                10 * 24 * 3600   // 10 days
        );

        return new JwtTokenResponse(accessToken, refreshToken,"success");
    }

    public JwtTokenResponse refreshToken(@Valid RefreshTokenRequestDto req) throws BadRequestException {

        String oldRefreshToken = req.getRefreshToken();

        if (oldRefreshToken == null || !authUtil.isRefreshToken(oldRefreshToken)) {
            throw new BadRequestException("Invalid refresh token");
        }

        if (!authUtil.validateToken(oldRefreshToken)) {
            throw new BadRequestException("Refresh token expired or invalid");
        }

        String username = authUtil.getUsernameFromToken(oldRefreshToken);
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
        List<? extends GrantedAuthority> roles = (List<? extends GrantedAuthority>) userDetails.getAuthorities();


        // Verify this refresh token is the newest one
        String stored = refreshTokenService.get(username);

        if (stored == null || !stored.equals(oldRefreshToken)) {
            throw new BadRequestException("Invalid or reused refresh token");
        }



        // At this point → token is valid and correct
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(userDetails, null, roles);

        String newAccessToken = authUtil.generateAccessToken(auth);
        String newRefreshToken = authUtil.generateRefreshToken(auth);

        // ROTATION:
        // 1. delete old refresh token
        refreshTokenService.delete(username);

        // 2. store new refresh token
        refreshTokenService.store(
                username,
                newRefreshToken,
                10 * 24 * 3600
        );

        return new JwtTokenResponse(newAccessToken, newRefreshToken, null);
    }

    public void logout() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null) return;

        Object principal = auth.getPrincipal();

        if (principal instanceof User user) {
            // Remove refresh token from Redis
            refreshTokenService.delete(user.getUsername());
        }

        // Clear security context
        SecurityContextHolder.clearContext();
    }



    public UserDto getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof User)) {
            return null;
        }
        User user = (User) auth.getPrincipal();
        return new UserDto(user.getId(), user.getUsername(), user.getEmail());
    }
}

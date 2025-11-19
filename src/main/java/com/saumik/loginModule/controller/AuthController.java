package com.saumik.loginModule.controller;

import com.saumik.loginModule.dto.LoginRequestDto;
import com.saumik.loginModule.dto.JwtTokenResponse;
import com.saumik.loginModule.dto.RefreshTokenRequestDto;
import com.saumik.loginModule.dto.SignupRequestDto;
import com.saumik.loginModule.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<JwtTokenResponse> login(@RequestBody @Valid LoginRequestDto req) {
        return ResponseEntity.ok(authService.login(req));
    }

    @PostMapping("/register")
    public ResponseEntity<JwtTokenResponse> register(@RequestBody @Valid SignupRequestDto req) {
        JwtTokenResponse result = authService.register(req);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequestDto req) throws BadRequestException {

        return ResponseEntity.ok(
                authService.refreshToken(req)
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        authService.logout();
        return ResponseEntity.ok("Logged out successfully");
    }



}

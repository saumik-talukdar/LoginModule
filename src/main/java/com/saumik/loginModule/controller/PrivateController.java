package com.saumik.loginModule.controller;

import com.saumik.loginModule.dto.UserDto;
import com.saumik.loginModule.entity.User;
import com.saumik.loginModule.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/private")
@RequiredArgsConstructor
public class PrivateController {

    private final AuthService authService;

    @GetMapping("/me")
    public ResponseEntity<UserDto> currentUser() {

        UserDto user = authService.getCurrentUser();
        return user != null ? ResponseEntity.ok(user) : ResponseEntity.status(401).build();
    }
}

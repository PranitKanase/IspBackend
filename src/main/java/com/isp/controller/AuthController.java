package com.isp.controller;

import com.isp.dto.AuthenticationResponse;
import com.isp.dto.LoginRequest;
import com.isp.dto.RegisterRequest;
import com.isp.dto.RegisterRequestProvider;
import com.isp.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody RegisterRequest registerRequest) {
        authService.signup(registerRequest);
        return new ResponseEntity<>(
                "User Registration successful", HttpStatus.OK);
    }

    @PostMapping("/signup/isp")
    public ResponseEntity<String> signupIsp(@RequestBody RegisterRequestProvider registerRequestProvider) {
        authService.signupIsp(registerRequestProvider);
        return new ResponseEntity<>(
                "Provider Registration successful", HttpStatus.OK);
    }

    @GetMapping("accountVerification/{token}")
    public ResponseEntity<String> verifyAccount(@PathVariable String token) {
        authService.verifyAccountProvider(token);
        return new ResponseEntity<>("Account activated successfully", HttpStatus.OK);
    }

    @GetMapping("accountVerification/isp/{token}")
    public ResponseEntity<String> verifyAccountIsp(@PathVariable String token) {
        authService.verifyAccountProvider(token);
        return new ResponseEntity<>("Account activated successfully", HttpStatus.OK);
    }

    @PostMapping("/login")
    public AuthenticationResponse login(@RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest);
    }
    @PostMapping("/login/isp")
    public AuthenticationResponse loginIsp(@RequestBody LoginRequest loginRequest) {
        return authService.loginIsp(loginRequest);
    }

}

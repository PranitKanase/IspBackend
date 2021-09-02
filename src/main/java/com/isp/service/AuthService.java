package com.isp.service;

import com.isp.dto.AuthenticationResponse;
import com.isp.dto.LoginRequest;
import com.isp.dto.RegisterRequest;
import com.isp.dto.RegisterRequestProvider;
import com.isp.exceptions.SpringIspException;
import com.isp.model.Isp;
import com.isp.model.NotificationEmail;
import com.isp.model.User;
import com.isp.model.VerificationToken;
import com.isp.repository.IspRepository;
import com.isp.repository.UserRepository;
import com.isp.repository.VerificationTokenRepository;
import com.isp.security.JwtProvider;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
@Transactional
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final MailService mailService;
    private final VerificationTokenRepository verificationTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final IspRepository ispRepository;

    @Transactional
    public  void signup(RegisterRequest registerRequest) {
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setEmail(registerRequest.getEmail());
        user.setCreated(Instant.now());
        user.setEnabled(false);
        user.setState(registerRequest.getState());
        user.setCity(registerRequest.getCity());
        user.setPincode(registerRequest.getPincode());


        userRepository.save(user);


        String token = generateVerificationToken(user);
        mailService.sendMail(new NotificationEmail("Please activate your account",user.getEmail(),"Thank you for signing up to ISP Provider, " +
                "please click on the below url to activate your account : " +
                "http://localhost:8080/api/auth/accountVerification/" + token));

    }

    public void signupIsp(RegisterRequestProvider registerRequestProvider) {
        Isp isp = new Isp();
        isp.setUsername(registerRequestProvider.getUsername());
        isp.setPassword(registerRequestProvider.getPassword());
        isp.setEmail(registerRequestProvider.getEmail());
        isp.setUrl(registerRequestProvider.getUrl());
        isp.setState(registerRequestProvider.getState());
        isp.setCity(registerRequestProvider.getCity());
        isp.setPincode(registerRequestProvider.getPincode());
        isp.setCreated(Instant.now());
        isp.setEnabled(false);

        ispRepository.save(isp);

        String token = generateVerificationToken(isp);
        mailService.sendMail(new NotificationEmail("Please activate your account",isp.getEmail(),"Thank you for signing up to ISP Provider, " +
                "please click on the below url to activate your account : " +
                "http://localhost:8080/api/auth/accountVerification/isp/" + token));
    }

    private String generateVerificationToken(User user) {
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);

        verificationTokenRepository.save(verificationToken);
        return token;
    }

    private String generateVerificationToken(Isp isp) {
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setIsp(isp);

        verificationTokenRepository.save(verificationToken);
        return token;
    }

    public void verifyAccount(String token) {
        Optional<VerificationToken> verificationToken =  verificationTokenRepository.findByToken(token);
        verificationToken.orElseThrow(() -> new SpringIspException("Invalid Token"));
        fetchUserandEnable(verificationToken.get());
    }

    public void verifyAccountProvider(String token) {
        Optional<VerificationToken> verificationToken =  verificationTokenRepository.findByToken(token);
        verificationToken.orElseThrow(() -> new SpringIspException("Invalid Token"));
        fetchIspandEnable(verificationToken.get());
    }

    @Transactional
    private void fetchUserandEnable(VerificationToken verificationToken) {
        String username = verificationToken.getUser().getUsername();
        User user = userRepository.findByUsername(username).orElseThrow(() -> new SpringIspException("User not found with name - "+ username));
        user.setEnabled(true);
        userRepository.save(user);
    }

    @Transactional
    private void fetchIspandEnable(VerificationToken verificationToken) {
        String ispname = verificationToken.getIsp().getUsername();
        Isp isp = ispRepository.findByUsername(ispname).orElseThrow(() -> new SpringIspException("Provider not found with name - "+ ispname));
        isp.setEnabled(true);
        ispRepository.save(isp);
    }

    public AuthenticationResponse login(LoginRequest loginRequest) {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        String token = jwtProvider.generateToken(authenticate);
        return new AuthenticationResponse(token,loginRequest.getUsername());
    }


    public AuthenticationResponse loginIsp(LoginRequest loginRequest) {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authenticate);
        String token = jwtProvider.generateToken(authenticate);
        return new AuthenticationResponse(token,loginRequest.getUsername());
    }
}

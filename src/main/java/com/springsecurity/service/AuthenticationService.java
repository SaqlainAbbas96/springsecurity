package com.springsecurity.service;

import com.springsecurity.config.JwtService;
import com.springsecurity.bean.AuthenticationRequest;
import com.springsecurity.bean.AuthenticationResponse;
import com.springsecurity.bean.RegisterRequest;
import com.springsecurity.repository.UserRepository;
import com.springsecurity.model.Role;
import com.springsecurity.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    /** Inject Password encoder service */
    private final PasswordEncoder passwordEncoder;

    /** Inject Jwt service */
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /** Allow to create and save user in db and return generated token */
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .pass(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        var jwt = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwt)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        var jwt = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwt)
                .build();
    }
}

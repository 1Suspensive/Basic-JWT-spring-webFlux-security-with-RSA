package org.suspensive.basicjwtwebfluxsecurity.controllers;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.suspensive.basicjwtwebfluxsecurity.models.dtos.AuthRequestDTO;
import org.suspensive.basicjwtwebfluxsecurity.models.dtos.AuthResponseDTO;
import org.suspensive.basicjwtwebfluxsecurity.services.AuthService;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(value = "/sign-up",produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Mono<AuthResponseDTO> signUp(@RequestBody final AuthRequestDTO authRequestDTO) {
        return authService.signUp(authRequestDTO);
    }

    @PostMapping(value = "/login",produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Mono<AuthResponseDTO> login(@RequestBody final AuthRequestDTO authRequestDTO) {
        return authService.login(authRequestDTO);
    }
}

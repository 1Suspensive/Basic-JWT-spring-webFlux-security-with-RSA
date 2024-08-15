package org.suspensive.basicjwtwebfluxsecurity.services;

import org.suspensive.basicjwtwebfluxsecurity.models.dtos.AuthRequestDTO;
import org.suspensive.basicjwtwebfluxsecurity.models.dtos.AuthResponseDTO;
import reactor.core.publisher.Mono;

public interface AuthService {
    Mono<AuthResponseDTO> signUp(AuthRequestDTO authRequestDTO);
    Mono<AuthResponseDTO> login(AuthRequestDTO authRequestDTO);
}

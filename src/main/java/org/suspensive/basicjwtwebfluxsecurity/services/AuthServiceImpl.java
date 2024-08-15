package org.suspensive.basicjwtwebfluxsecurity.services;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.suspensive.basicjwtwebfluxsecurity.models.Role;
import org.suspensive.basicjwtwebfluxsecurity.models.User;
import org.suspensive.basicjwtwebfluxsecurity.models.dtos.AuthRequestDTO;
import org.suspensive.basicjwtwebfluxsecurity.models.dtos.AuthResponseDTO;
import org.suspensive.basicjwtwebfluxsecurity.repositories.UserReactiveMongoRepository;
import org.suspensive.basicjwtwebfluxsecurity.utils.JwtUtils;
import reactor.core.publisher.Mono;

import java.util.Set;

@Service
@Transactional
public class AuthServiceImpl implements AuthService{

    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final UserReactiveMongoRepository userRepository;

    public AuthServiceImpl(JwtUtils jwtUtils, PasswordEncoder passwordEncoder, UserReactiveMongoRepository userRepository) {
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    @Override
    public Mono<AuthResponseDTO> signUp(AuthRequestDTO authRequestDTO) {
        Mono<Boolean> userExists = userRepository.findByUsername(authRequestDTO.username()).hasElement();
        return userExists
                .flatMap(exists -> exists ?
                        Mono.error(new Throwable("User already exists")) :
                        userRepository.save(new User(
                                null,
                                authRequestDTO.username(),
                                passwordEncoder.encode(authRequestDTO.password()),
                                Set.of(Role.DEFAULT_ROLE),
                                true
                        )))
                .map(user -> new AuthResponseDTO(user.getUsername(),"User registered successfully",jwtUtils.generateToken(user),true));
    }

    @Override
    public Mono<AuthResponseDTO> login(AuthRequestDTO authRequestDTO) {
        return userRepository.findByUsername(authRequestDTO.username())
                .switchIfEmpty(Mono.error(new Throwable("User not found")))
                .filter(user -> passwordEncoder.matches(authRequestDTO.password(),user.getPassword()))
                .switchIfEmpty(Mono.error(new Throwable("Incorrect password!")))
                .map(user -> new AuthResponseDTO(user.getUsername(),"Logged successfully",jwtUtils.generateToken(user),true));
    }

}

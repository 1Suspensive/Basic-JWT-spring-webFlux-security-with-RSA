package org.suspensive.basicjwtwebfluxsecurity.utils;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {
    private final Algorithm algorithm;

    @Value("${security.jwt.issuer}")
    private String jwtIssuer;

    public JwtUtils(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    public String generateToken(UserDetails user) {

        String authorities = user.getAuthorities()
                .stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return  JWT.create()
                .withIssuer(this.jwtIssuer)
                .withSubject(user.getUsername())
                .withClaim("authorities",authorities)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 90000))
                .withJWTId(UUID.randomUUID().toString())
                .withNotBefore(new Date(System.currentTimeMillis()))
                .sign(algorithm);
    }

    public Mono<DecodedJWT> verifyToken(String token) {
        try{
            return Mono.just(JWT.require(algorithm)
                        .withIssuer(this.jwtIssuer)
                        .build())
                    .map(verifier -> verifier.verify(token));
        }catch (SignatureVerificationException
                 | AlgorithmMismatchException
                 | TokenExpiredException
                 | InvalidClaimException e) {
        return Mono.error(() -> new RuntimeException("Token Verification Failed - {}", e));
    }
    }
}

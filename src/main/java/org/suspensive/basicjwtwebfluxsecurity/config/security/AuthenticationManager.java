package org.suspensive.basicjwtwebfluxsecurity.config.security;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;
import org.suspensive.basicjwtwebfluxsecurity.utils.JwtUtils;
import reactor.core.publisher.Mono;

import java.util.Collection;

@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private final JwtUtils jwtUtils;

    public AuthenticationManager(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication.getCredentials().toString())
                .flatMap(jwtUtils::verifyToken)
                .flatMap(this::getAuthentication);
    }

    private Mono<Authentication> getAuthentication(DecodedJWT decodedJWT){
        return Mono.just(new UsernamePasswordAuthenticationToken(
                decodedJWT.getSubject(),
                null,
                getAuthorities(decodedJWT)
        ));
    }

    private Collection<GrantedAuthority> getAuthorities(DecodedJWT decodedJWT) {
        String authoritiesClaim = decodedJWT.getClaim("authorities").asString();
        return AuthorityUtils.commaSeparatedStringToAuthorityList(authoritiesClaim);
    }
}

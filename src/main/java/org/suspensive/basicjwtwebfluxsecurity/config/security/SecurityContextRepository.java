package org.suspensive.basicjwtwebfluxsecurity.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
@Slf4j
public class SecurityContextRepository implements ServerSecurityContextRepository {

    private final AuthenticationManager authenticationManager;

    public SecurityContextRepository(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        throw  new UnsupportedOperationException("Not Supported");
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        String token = exchange.getAttribute("token");

        log.debug("Loading SecurityContext for request with token: {}", token);

        if (token == null || token.isEmpty()) {
            log.warn("Token is missing or empty. Returning empty Mono.");
            return Mono.empty();
        }

        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(token, token))
                .map(authentication -> (SecurityContext) new SecurityContextImpl(authentication))
                .doOnNext(context -> log.debug("SecurityContext loaded successfully for user: {}", context.getAuthentication().getName()))
                .doOnError(error -> log.error("Error loading SecurityContext: ", error));
    }
}

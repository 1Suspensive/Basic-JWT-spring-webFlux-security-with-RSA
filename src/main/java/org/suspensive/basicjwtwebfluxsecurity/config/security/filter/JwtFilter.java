package org.suspensive.basicjwtwebfluxsecurity.config.security.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class JwtFilter implements WebFilter {

    private final String TOKEN_PREFIX = "Bearer ";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("Filter starts");
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        if(path.contains("/auth")){
            return chain.filter(exchange);
        }
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if(authHeader == null || !authHeader.startsWith(TOKEN_PREFIX)){
            return Mono.error(new Throwable("Token invalid!"));
        }
        exchange.getAttributes().put("token", authHeader.substring(TOKEN_PREFIX.length()));
        return chain.filter(exchange);
    }
}

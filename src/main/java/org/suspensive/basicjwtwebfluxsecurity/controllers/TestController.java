package org.suspensive.basicjwtwebfluxsecurity.controllers;

import org.springframework.http.MediaType;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class TestController {

    @GetMapping(value = "/hello",produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Mono<String> hello(){
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .map(authentication -> "Hello " + authentication.getName());
    }
}

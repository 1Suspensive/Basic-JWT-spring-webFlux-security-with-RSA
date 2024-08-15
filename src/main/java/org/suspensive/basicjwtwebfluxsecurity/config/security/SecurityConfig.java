package org.suspensive.basicjwtwebfluxsecurity.config.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.suspensive.basicjwtwebfluxsecurity.config.security.filter.JwtFilter;
import org.suspensive.basicjwtwebfluxsecurity.models.Role;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http,
                                                final JwtFilter jwtFilter,
                                                final AuthenticationManager authenticationManager,
                                                final SecurityContextRepository securityContextRepository){
        return http
                .addFilterAfter(jwtFilter,SecurityWebFiltersOrder.FIRST)
                .authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .authorizeExchange(exchange ->{
                        exchange.pathMatchers(HttpMethod.POST,"/auth/**").permitAll();
                        exchange.pathMatchers(HttpMethod.GET,"/hello").hasRole(Role.DEFAULT_ROLE.getRoleName());
                        exchange.anyExchange().authenticated();
                        })
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}

package com.example.issuer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/.well-known/openid-credential-issuer").permitAll()
                        .requestMatchers("/.well-known/jwks.json").permitAll()
                        .requestMatchers("/.well-known/status-list/**").permitAll()
                        .requestMatchers("/admin/revoke").permitAll()
                        .requestMatchers("/credential/nonce").permitAll()
                        .anyRequest().authenticated()
                )
                // Spring Security 6.5+ has built-in DPoP support enabled by default
                // It automatically handles: DPoP scheme extraction, proof validation,
                // ath claim verification, and cnf.jkt binding verification
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults() )
                );

        return http.build();
    }

}

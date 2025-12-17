package com.example.walletprovider.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration for Wallet Provider.
 *
 * PoC: All endpoints are public. Security is provided by:
 * - Proof JWT validates wallet owns the attested key
 * - Android Key Attestation validates hardware-backed key
 * - Nonce prevents replay attacks
 *
 * Production: Add wallet authentication via OAuth2 Client Credentials or WIA.
 * The Wallet Provider Interface (WPI) is proprietary per ARF - not standardized.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                );

        return http.build();
    }
}

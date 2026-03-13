package dev.kmandalas.trustvalidator.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security is intentionally open — in production, the trust-validator is an internal service
 * reachable only via service-to-service LAN communication. The actual security posture (mTLS,
 * API keys, service mesh sidecar, or network-level isolation) depends on the zero-trust model
 * adopted by the deployment environment.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/trust", "/validate", "/public/**", "/webjars/**", "/actuator/**").permitAll()
                .anyRequest().permitAll()
            );
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            org.springframework.core.env.Environment env
    ) {
        var config = new CorsConfiguration();
        var origins = env.getProperty("cors.origins");
        if (origins != null && !origins.isBlank()) config.setAllowedOriginPatterns(List.of(origins.split(",")));
        var methods = env.getProperty("cors.methods");
        if (methods != null && !methods.isBlank()) config.setAllowedMethods(List.of(methods.split(",")));
        var headers = env.getProperty("cors.headers");
        if (headers != null && !headers.isBlank()) {
            config.setAllowedHeaders(List.of(headers.split(",")));
            config.setExposedHeaders(List.of(headers.split(",")));
        }
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

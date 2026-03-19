package dev.kmandalas.walletprovider.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

/**
 * Security configuration for Wallet Provider.
 *
 * PoC: All endpoints are public. Security is provided by:
 * - Proof JWT validates wallet owns the attested key
 * - Android Key Attestation validates hardware-backed key
 * - Nonce prevents replay attacks
 * - Firebase App Check verifies app genuineness (WIAM_04)
 *
 * Production: The Wallet Provider Interface (WPI) is proprietary per ARF - not standardized.
 */
@Configuration
@EnableConfigurationProperties({AppCheckProperties.class, AdminApiProperties.class})
public class SecurityConfig {

    private final AppCheckProperties appCheckProperties;
    private final AdminApiProperties adminApiProperties;

    public SecurityConfig(AppCheckProperties appCheckProperties, AdminApiProperties adminApiProperties) {
        this.appCheckProperties = appCheckProperties;
        this.adminApiProperties = adminApiProperties;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(new AppCheckFilter(appCheckProperties), AuthorizationFilter.class)
                .addFilterBefore(new AdminApiKeyFilter(adminApiProperties), AppCheckFilter.class);

        return http.build();
    }
}

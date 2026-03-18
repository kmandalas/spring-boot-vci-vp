package dev.kmandalas.qtspmock.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final QtspProperties qtspProperties;

    public SecurityConfig(QtspProperties qtspProperties) {
        this.qtspProperties = qtspProperties;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/csc/v2/info").permitAll()
                        .requestMatchers("/csc/v2/**").permitAll()
                        .requestMatchers("/", "/dashboard/**", "/webjars/**", "/css/**", "/img/**").permitAll()
                        .anyRequest().permitAll()
                )
                .addFilterBefore(new CscApiKeyFilter(qtspProperties),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

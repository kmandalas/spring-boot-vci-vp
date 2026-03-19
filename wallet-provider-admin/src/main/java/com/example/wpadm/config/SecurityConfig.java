package com.example.wpadm.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;

@Configuration
@EnableWebSecurity
@EnableMultiFactorAuthentication(authorities = {})
public class SecurityConfig {

    private final TotpAuthenticationHandler totpAuthenticationHandler;

    public SecurityConfig(TotpAuthenticationHandler totpAuthenticationHandler) {
        this.totpAuthenticationHandler = totpAuthenticationHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * If the session expired and the CSRF token is stale, a POST /logout gets a 403.
     * Redirect that specific case to the login page instead of showing an error.
     */
    private AccessDeniedHandler logoutAwareAccessDeniedHandler() {
        var defaultHandler = new AccessDeniedHandlerImpl();
        return (HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex) -> {
            if ("POST".equals(request.getMethod()) && "/logout".equals(request.getRequestURI())) {
                request.getSession(false); // don't create a new session
                response.sendRedirect(request.getContextPath() + "/login?expired=true");
            } else {
                defaultHandler.handle(request, response, ex);
            }
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // Public resources
                .requestMatchers("/css/**", "/js/**", "/images/**", "/webjars/**").permitAll()
                .requestMatchers("/login", "/error").permitAll()
                // TOTP pages require password factor (single-factor authenticated)
                .requestMatchers("/totp/**", "/setup-totp/**").hasAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                // Protected pages require TOTP factor (fully MFA authenticated)
                .requestMatchers("/dashboard/**", "/wua/**").hasAuthority(TotpAuthenticationHandler.TOTP_AUTHORITY)
                // All other authenticated requests also need TOTP
                .anyRequest().hasAuthority(TotpAuthenticationHandler.TOTP_AUTHORITY)
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .successHandler(totpAuthenticationHandler)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            )
            .exceptionHandling(ex -> ex
                .accessDeniedHandler(logoutAwareAccessDeniedHandler())
            )
            .sessionManagement(session -> session
                .maximumSessions(1)
                .expiredUrl("/login?expired=true")
            );

        return http.build();
    }
}

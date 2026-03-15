package dev.kmandalas.qtspmock.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

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
                        .requestMatchers("/csc/v2/**").authenticated()
                        .requestMatchers("/", "/dashboard/**", "/webjars/**", "/css/**", "/img/**").permitAll()
                        .anyRequest().permitAll()
                )
                .addFilterBefore(new ApiKeyFilter(qtspProperties.getApiKey()),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Simple static API key filter for CSC API endpoints.
     */
    static class ApiKeyFilter extends OncePerRequestFilter {

        private final String expectedApiKey;

        ApiKeyFilter(String expectedApiKey) {
            this.expectedApiKey = expectedApiKey;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                        FilterChain filterChain) throws ServletException, IOException {

            String path = request.getRequestURI();

            // Skip auth for info endpoint and non-CSC paths
            if ("/csc/v2/info".equals(path) || !path.startsWith("/csc/v2/")) {
                filterChain.doFilter(request, response);
                return;
            }

            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"missing_api_key\", \"error_description\": \"Bearer token required\"}");
                return;
            }

            String token = authHeader.substring(7);
            if (!expectedApiKey.equals(token)) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"invalid_api_key\", \"error_description\": \"Invalid API key\"}");
                return;
            }

            // Set authentication in SecurityContext so Spring Security's .authenticated() passes
            var auth = new UsernamePasswordAuthenticationToken(
                    "api-client", null, List.of(new SimpleGrantedAuthority("ROLE_API"))
            );
            SecurityContextHolder.getContext().setAuthentication(auth);

            filterChain.doFilter(request, response);
        }
    }

}

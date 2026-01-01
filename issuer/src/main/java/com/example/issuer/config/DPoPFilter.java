package com.example.issuer.config;

import com.example.issuer.service.DPoPValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Filter that enforces DPoP validation for DPoP-bound access tokens.
 *
 * NOTE: Kept for reference. Spring Security 6.5+ has built-in DPoP support.
 */
// @Component  // Disabled - using Spring Security's built-in DPoP support
public class DPoPFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DPoPFilter.class);

    private final DPoPValidator dpopValidator;

    public DPoPFilter(DPoPValidator dpopValidator) {
        this.dpopValidator = dpopValidator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();

            // Check if token is DPoP-bound (has cnf.jkt claim)
            Map<String, Object> cnf = jwt.getClaim("cnf");
            if (cnf != null && cnf.containsKey("jkt")) {
                String expectedJkt = (String) cnf.get("jkt");

                // Verify Authorization header uses DPoP scheme
                String authHeader = request.getHeader("Authorization");
                if (authHeader == null || !authHeader.startsWith("DPoP ")) {
                    log.warn("DPoP-bound token used with non-DPoP authorization scheme");
                    sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                            "invalid_token", "DPoP-bound token requires 'DPoP' authorization scheme");
                    return;
                }

                // Get DPoP proof header
                String dpopHeader = request.getHeader("DPoP");
                if (dpopHeader == null || dpopHeader.isBlank()) {
                    log.warn("Missing DPoP proof header");
                    sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                            "invalid_dpop_proof", "DPoP proof header is required");
                    return;
                }

                // Build request URI
                String requestUri = request.getRequestURL().toString();

                // Validate DPoP proof
                if (!dpopValidator.validate(dpopHeader, request.getMethod(), requestUri, expectedJkt)) {
                    log.warn("DPoP proof validation failed for {}", requestUri);
                    sendError(response, HttpServletResponse.SC_UNAUTHORIZED,
                            "invalid_dpop_proof", "DPoP proof validation failed");
                    return;
                }

                log.info("DPoP proof validated for {}", requestUri);
            }
        }

        filterChain.doFilter(request, response);
    }

    private void sendError(HttpServletResponse response, int status, String error, String description)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(
                "{\"error\":\"" + error + "\",\"error_description\":\"" + description + "\"}");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Skip DPoP for public endpoints
        return path.startsWith("/.well-known/");
    }
}

package dev.kmandalas.qtspmock.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CscApiKeyFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(CscApiKeyFilter.class);

    private final QtspProperties properties;

    public CscApiKeyFilter(QtspProperties properties) {
        this.properties = properties;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/csc/v2/") || "/csc/v2/info".equals(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("🔒 CSC API: missing Bearer token from {}", request.getRemoteAddr());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"missing_api_key\", \"error_description\": \"Bearer token required\"}");
            return;
        }

        String token = authHeader.substring(7);
        if (!properties.getApiKey().equals(token)) {
            log.warn("🔒 CSC API: invalid API key from {}", request.getRemoteAddr());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"invalid_api_key\", \"error_description\": \"Invalid API key\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}

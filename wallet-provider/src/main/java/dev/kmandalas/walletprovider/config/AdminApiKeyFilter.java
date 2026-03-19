package dev.kmandalas.walletprovider.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AdminApiKeyFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AdminApiKeyFilter.class);
    private static final String HEADER_NAME = "X-Admin-Api-Key";

    private final AdminApiProperties properties;

    public AdminApiKeyFilter(AdminApiProperties properties) {
        this.properties = properties;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/wp/admin/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!properties.enabled()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        String apiKey = request.getHeader(HEADER_NAME);
        if (apiKey == null || !apiKey.equals(properties.apiKey())) {
            log.warn("🔒 Admin API: invalid or missing API key from {}", request.getRemoteAddr());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid API key");
            return;
        }

        filterChain.doFilter(request, response);
    }
}

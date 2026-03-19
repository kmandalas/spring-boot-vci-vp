package dev.kmandalas.walletprovider.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.Set;

public class AppCheckFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AppCheckFilter.class);
    private static final String FIREBASE_JWKS_URL = "https://firebaseappcheck.googleapis.com/v1/jwks";
    private static final String HEADER_NAME = "X-Firebase-AppCheck";

    private final AppCheckProperties properties;
    private final DefaultJWTProcessor<SecurityContext> jwtProcessor;

    public AppCheckFilter(AppCheckProperties properties) {
        this.properties = properties;
        this.jwtProcessor = buildJwtProcessor();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!properties.enabled()) return true;
        String path = request.getRequestURI();
        return path.contains("/.well-known/") || path.contains("/wua/status/") || path.startsWith("/wp/admin/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = request.getHeader(HEADER_NAME);
        if (token == null || token.isBlank()) {
            log.warn("Missing App Check token for {}", request.getRequestURI());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing App Check token");
            return;
        }

        try {
            JWTClaimsSet claims = jwtProcessor.process(token, null);

            String expectedIssuer = "https://firebaseappcheck.googleapis.com/" + properties.projectNumber();
            if (!expectedIssuer.equals(claims.getIssuer())) {
                log.warn("App Check token issuer mismatch: expected={}, got={}", expectedIssuer, claims.getIssuer());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid App Check token issuer");
                return;
            }

            String expectedAud = "projects/" + properties.projectNumber();
            var audience = claims.getAudience();
            if (audience == null || !audience.contains(expectedAud)) {
                log.warn("App Check token audience mismatch: expected={}, got={}", expectedAud, audience);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid App Check token audience");
                return;
            }

            String subject = claims.getSubject();
            if (properties.appId() != null && !properties.appId().isBlank() && !properties.appId().equals(subject)) {
                log.warn("App Check token subject mismatch: expected={}, got={}", properties.appId(), subject);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid App Check token subject");
                return;
            }

            log.debug("App Check token verified for app: {}", subject);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.warn("App Check token verification failed: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid App Check token");
        }
    }

    private DefaultJWTProcessor<SecurityContext> buildJwtProcessor() {
        try {
            var jwkSource = JWKSourceBuilder
                    .create(URI.create(FIREBASE_JWKS_URL).toURL())
                    .cache(true)
                    .build();

            var keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

            var processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(keySelector);

            // Verify standard claims (exp, etc.) — iss/sub/aud checked manually in doFilterInternal
            var claimsVerifier = new DefaultJWTClaimsVerifier<>(
                    new JWTClaimsSet.Builder().build(),
                    Set.of("iss", "sub", "exp", "aud")
            );
            processor.setJWTClaimsSetVerifier(claimsVerifier);

            return processor;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize App Check JWT processor", e);
        }
    }

}

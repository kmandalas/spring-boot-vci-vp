package com.example.authserver.wia;

import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * Extracts OAuth Attestation-Based Client Authentication from HTTP headers.
 * Looks for OAuth-Client-Attestation (WIA) and OAuth-Client-Attestation-PoP headers.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/">
 *      draft-ietf-oauth-attestation-based-client-auth</a>
 */
public class WalletAttestationAuthenticationConverter implements AuthenticationConverter {

    private static final Logger logger = LoggerFactory.getLogger(WalletAttestationAuthenticationConverter.class);

    private static final String OAUTH_CLIENT_ATTESTATION_HEADER = "OAuth-Client-Attestation";
    private static final String OAUTH_CLIENT_ATTESTATION_POP_HEADER = "OAuth-Client-Attestation-PoP";
    private static final String DPOP_HEADER = "DPoP";

    @Override
    public Authentication convert(HttpServletRequest request) {
        String wiaJwt = request.getHeader(OAUTH_CLIENT_ATTESTATION_HEADER);
        String popJwt = request.getHeader(OAUTH_CLIENT_ATTESTATION_POP_HEADER);
        String dpopJwt = request.getHeader(DPOP_HEADER);

        // Both WIA headers must be present for attestation-based authentication
        if (wiaJwt == null || popJwt == null) {
            return null;
        }

        logger.debug("Found OAuth attestation headers, extracting client_id from WIA");

        try {
            // Parse WIA JWT to extract client_id from sub claim
            SignedJWT wia = SignedJWT.parse(wiaJwt);
            String clientId = wia.getJWTClaimsSet().getSubject();

            if (clientId == null || clientId.isBlank()) {
                logger.warn("WIA JWT missing 'sub' claim (client_id)");
                return null;
            }

            logger.debug("Extracted client_id from WIA: {}", clientId);
            // Include DPoP JWT for key binding verification (may be null)
            return new WalletAttestationAuthenticationToken(clientId, wiaJwt, popJwt, dpopJwt);

        } catch (Exception e) {
            logger.warn("Failed to parse WIA JWT for client_id extraction: {}", e.getMessage());
            return null;
        }
    }

}

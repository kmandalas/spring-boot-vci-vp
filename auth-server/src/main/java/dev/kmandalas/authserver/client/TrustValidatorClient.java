package dev.kmandalas.authserver.client;

import com.nimbusds.jose.util.Base64;
import dev.kmandalas.authserver.config.WalletAttestationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Optional;

/**
 * HTTP client for the trust-validator service.
 * Validates X.509 certificate chains against configured trust anchors (local JKS or EU LoTL).
 */
@Component
public class TrustValidatorClient {

    private static final Logger logger = LoggerFactory.getLogger(TrustValidatorClient.class);

    private final RestClient restClient;

    public record TrustRequest(List<String> chain, String verificationContext, String useCase) {}
    public record TrustResponse(boolean trusted, String trustAnchor) {}

    public TrustValidatorClient(RestClient.Builder builder, WalletAttestationProperties properties) {
        this.restClient = builder.baseUrl(properties.getTrustValidator().getUrl()).build();
    }

    /**
     * Validates an X.509 certificate chain against the trust-validator service.
     *
     * @param x5cChain  Base64-encoded DER certs from the JWT x5c header (leaf first)
     * @param context   verification context (e.g., "WalletInstanceAttestation")
     * @return Optional trustAnchor if trusted, empty if not trusted or on error
     */
    public Optional<String> isTrusted(List<Base64> x5cChain, String context) {
        try {
            List<String> chain = x5cChain.stream().map(Base64::toString).toList();
            TrustResponse response = restClient
                    .post()
                    .uri("/trust")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new TrustRequest(chain, context, null))
                    .retrieve()
                    .body(TrustResponse.class);
            if (response != null && response.trusted()) {
                logger.debug("🔗 Trust validator: chain trusted (context={}, anchor={})", context, response.trustAnchor());
                return Optional.ofNullable(response.trustAnchor());
            }
            logger.warn("⚠️ Trust validator: chain NOT trusted for context={}", context);
            return Optional.empty();
        } catch (Exception e) {
            logger.warn("⚠️ Trust validator call failed (context={}): {}", context, e.getMessage());
            return Optional.empty();
        }
    }
}

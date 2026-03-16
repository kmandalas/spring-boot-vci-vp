package dev.kmandalas.walletprovider.client;

import dev.kmandalas.walletprovider.config.QtspProperties;
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

    record TrustRequest(List<String> chain, String verificationContext, String useCase) {}
    record TrustResponse(boolean trusted, String trustAnchor) {}

    public TrustValidatorClient(RestClient.Builder builder, QtspProperties properties) {
        this.restClient = builder.baseUrl(properties.getTrustValidatorUrl()).build();
    }

    /**
     * Validates an X.509 certificate chain against the trust-validator service.
     *
     * @param certChainBase64 Base64-encoded DER certs (leaf first)
     * @param context         verification context (e.g., "QTSPSigningCertificate")
     * @return Optional trustAnchor if trusted, empty if not trusted or on error
     */
    public Optional<String> isTrusted(List<String> certChainBase64, String context) {
        try {
            TrustResponse response = restClient
                    .post()
                    .uri("/trust")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new TrustRequest(certChainBase64, context, null))
                    .retrieve()
                    .body(TrustResponse.class);
            if (response != null && response.trusted()) {
                logger.debug("🔗 Trust validator: QTSP chain trusted (context={}, anchor={})", context, response.trustAnchor());
                return Optional.ofNullable(response.trustAnchor());
            }
            logger.warn("⚠️ Trust validator: QTSP chain NOT trusted for context={}", context);
            return Optional.empty();
        } catch (Exception e) {
            logger.warn("⚠️ Trust validator call failed (context={}): {}", context, e.getMessage());
            return Optional.empty();
        }
    }

}

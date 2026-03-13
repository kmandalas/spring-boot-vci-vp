package dev.kmandalas.trustvalidator.config;

import dev.kmandalas.trustvalidator.model.VerificationContextTO;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * Blocking trust chain validator — returns the trust-anchor certificate if the chain
 * is trusted, or {@link Optional#empty()} if not.
 */
@FunctionalInterface
public interface TrustChainValidator {
    Optional<X509Certificate> isTrusted(List<X509Certificate> chain, VerificationContextTO context, String useCase);
}

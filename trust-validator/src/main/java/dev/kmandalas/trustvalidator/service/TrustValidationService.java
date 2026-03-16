package dev.kmandalas.trustvalidator.service;

import dev.kmandalas.trustvalidator.config.TrustChainValidator;
import dev.kmandalas.trustvalidator.model.*;
import dev.kmandalas.trustvalidator.util.X509Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.List;

@Service
public class TrustValidationService {

    private static final Logger log = LoggerFactory.getLogger(TrustValidationService.class);

    private final TrustChainValidator isChainTrusted;

    public TrustValidationService(TrustChainValidator isChainTrusted) {
        this.isChainTrusted = isChainTrusted;
    }

    public Object validate(TrustRequestTO request) {
        // 1. Validate and decode the certificate chain
        if (request.chain() == null || request.chain().isEmpty()) {
            log.warn("Rejected request: certificate chain is empty (context={})", request.verificationContext());
            return new ErrorResponseTO.ClientError("Certificate chain must not be empty");
        }
        List<X509Certificate> chain;
        try {
            chain = request.chain().stream()
                    .map(X509Utils::decodeBase64EncodedDer)
                    .toList();
        } catch (Exception e) {
            log.warn("Rejected request: failed to decode certificate chain (context={}): {}",
                    request.verificationContext(), e.getMessage());
            return new ErrorResponseTO.ClientError("Invalid certificate in chain: " + e.getMessage());
        }

        log.info("Trust validation request: context={}, chainLength={}, useCase={}",
                request.verificationContext(), chain.size(), request.useCase());

        // 2. Validate useCase for contexts that require it
        if (requiresUseCase(request.verificationContext()) &&
                (request.useCase() == null || request.useCase().isBlank())) {
            log.warn("Rejected request: useCase required but missing for context={}", request.verificationContext());
            return new ErrorResponseTO.ClientError("useCase is required for context " + request.verificationContext());
        }

        // 3. Validate chain
        try {
            var result = isChainTrusted.isTrusted(chain, request.verificationContext(), request.useCase());
            if (result.isPresent()) {
                var anchor = result.get();
                log.info("Chain TRUSTED: context={}, subject='{}', anchor='{}'",
                        request.verificationContext(),
                        chain.getFirst().getSubjectX500Principal().getName(),
                        anchor.getSubjectX500Principal().getName());
                return TrustResponseTO.trusted(X509Utils.base64Encode(anchor));
            } else {
                log.warn("Chain NOT trusted: context={}, subject='{}'",
                        request.verificationContext(),
                        chain.getFirst().getSubjectX500Principal().getName());
                return TrustResponseTO.notTrusted();
            }
        } catch (Exception e) {
            log.error("Trust validation error: context={}, error={}", request.verificationContext(), e.getMessage(), e);
            return new ErrorResponseTO.ServerError("Trust validation failed: " + e.getMessage());
        }
    }

    private boolean requiresUseCase(VerificationContextTO ctx) {
        return ctx == VerificationContextTO.EAA
                || ctx == VerificationContextTO.EAAStatus
                || ctx == VerificationContextTO.Custom;
    }
}

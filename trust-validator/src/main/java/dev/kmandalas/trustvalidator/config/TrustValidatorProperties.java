package dev.kmandalas.trustvalidator.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.util.List;

@ConfigurationProperties("trust-validator")
public record TrustValidatorProperties(
        DSSProperties dss,
        TrustSourcesProperties trustSources
) {
    public TrustValidatorProperties {
        // dss may be null if no LoTL/LoTE is configured (KeyStore-only mode)
    }

    public record DSSProperties(Path cacheLocation) {}

    public record TrustSourcesProperties(
            TrustedListsProperties walletProviders,
            TrustedListsProperties pidProviders,
            TrustedListsProperties qeaaProviders,
            TrustedListsProperties pubEaaProviders,
            List<EaaTrustedListsProperties> eaaProviders,
            TrustedListsProperties wrpacProviders,
            TrustedListsProperties wrprcProviders,
            KeyStoreProperties keyStore
    ) {}

    public record TrustedListsProperties(LoTLProperties lotl, LoTEProperties lote) {
        public boolean isConfigured() {
            return lotl != null || lote != null;
        }
    }

    public record LoTLProperties(
            URL location,
            KeyStoreProperties signatureVerification,
            URI issuanceService,
            URI revocationService
    ) {}

    public record LoTEProperties(
            URL location,
            URI issuanceService,
            URI revocationService
    ) {}

    public record KeyStoreProperties(
            Resource location,
            String keyStoreType,
            String password
    ) {
        public KeyStoreProperties {
            if (keyStoreType == null) keyStoreType = "JKS";
        }
    }

    public record EaaTrustedListsProperties(
            String useCase,
            LoTLProperties lotl,
            LoTEProperties lote
    ) {}
}

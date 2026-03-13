package dev.kmandalas.trustvalidator.config;

import dev.kmandalas.trustvalidator.model.VerificationContextTO;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Scheduled;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
@EnableConfigurationProperties(TrustValidatorProperties.class)
public class TrustValidatorConfig {

    private static final Logger log = LoggerFactory.getLogger(TrustValidatorConfig.class);

    private final TrustValidatorProperties properties;

    /** One TLValidationJob per context key — refreshed on schedule. */
    private final Map<String, TLValidationJob> validationJobs = new LinkedHashMap<>();

    /** One TrustedListsCertificateSource per context key — populated by corresponding job. */
    private final Map<String, TrustedListsCertificateSource> lotlCertSources = new LinkedHashMap<>();

    public TrustValidatorConfig(TrustValidatorProperties properties) {
        this.properties = properties;
    }

    @Bean(destroyMethod = "shutdown")
    public ExecutorService dssExecutorService() {
        return Executors.newCachedThreadPool();
    }

    @Bean
    public TrustChainValidator isChainTrusted(ExecutorService dssExecutorService) throws Exception {
        // Build LoTL jobs (one per configured context)
        if (properties.dss() != null && properties.dss().cacheLocation() != null) {
            buildLotlJobs(dssExecutorService);
            // Initial offline refresh from existing cache (won't fail on empty cache)
            validationJobs.forEach((key, job) -> {
                try {
                    job.offlineRefresh();
                } catch (Exception e) {
                    log.warn("Offline LoTL refresh failed for context '{}': {}", key, e.getMessage());
                }
            });
            log.info("Initialised {} LoTL trust source(s)", validationJobs.size());
        }

        // LoTE: not yet supported — requires separate JSON-based trust list loading
        if (properties.trustSources() != null && hasLoteConfig()) {
            log.warn("LoTE trust sources configured but not yet supported — ignoring");
        }

        // KeyStore (optional fallback)
        final KeyStore keyStore;
        if (properties.trustSources() != null && properties.trustSources().keyStore() != null) {
            keyStore = loadKeyStore(properties.trustSources().keyStore());
            log.info("Configured KeyStore trust source");
        } else {
            keyStore = null;
        }

        if (validationJobs.isEmpty() && keyStore == null) {
            log.warn("No trust sources configured — all chains will be reported as NOT trusted");
        }

        return (chain, contextTO, useCase) -> {
            // Try LoTL first (context-specific)
            var key = contextKey(contextTO, useCase);
            var certSource = lotlCertSources.get(key);
            if (certSource != null) {
                var result = validateChain(chain, certSource);
                if (result.isPresent()) return result;
            }
            // Fall back to KeyStore
            if (keyStore != null) {
                return validateWithKeyStore(chain, keyStore);
            }
            return Optional.empty();
        };
    }

    /** Called by {@link dev.kmandalas.trustvalidator.service.DssCacheCleanupService} schedule — triggers online LoTL refresh. */
    @Scheduled(fixedRateString = "${trust-validator.lotl.refresh-rate-ms:3600000}")
    public void refreshLoTL() {
        if (validationJobs.isEmpty()) return;
        log.debug("Refreshing {} LoTL source(s) online", validationJobs.size());
        validationJobs.forEach((key, job) -> {
            try {
                job.onlineRefresh();
                log.info("LoTL online refresh succeeded for context '{}'", key);
            } catch (Exception e) {
                log.warn("LoTL online refresh failed for context '{}': {}", key, e.getMessage());
            }
        });
    }

    // ---------------------------------------------------------------------------
    // LoTL job construction
    // ---------------------------------------------------------------------------

    private void buildLotlJobs(ExecutorService executor) {
        var cacheDir = properties.dss().cacheLocation().toFile();
        var ts = properties.trustSources();
        if (ts == null) return;

        if (ts.walletProviders() != null && ts.walletProviders().lotl() != null) {
            var p = ts.walletProviders().lotl();
            addJob(VerificationContextTO.WalletInstanceAttestation.name(), null, p, cacheDir, executor);
            addJob(VerificationContextTO.WalletUnitAttestation.name(), null, p, cacheDir, executor);
            addJob(VerificationContextTO.WalletUnitAttestationStatus.name(), null, p, cacheDir, executor);
        }
        if (ts.pidProviders() != null && ts.pidProviders().lotl() != null) {
            var p = ts.pidProviders().lotl();
            addJob(VerificationContextTO.PID.name(), null, p, cacheDir, executor);
            addJob(VerificationContextTO.PIDStatus.name(), null, p, cacheDir, executor);
        }
        if (ts.qeaaProviders() != null && ts.qeaaProviders().lotl() != null) {
            var p = ts.qeaaProviders().lotl();
            addJob(VerificationContextTO.QEAA.name(), null, p, cacheDir, executor);
            addJob(VerificationContextTO.QEAAStatus.name(), null, p, cacheDir, executor);
        }
        if (ts.pubEaaProviders() != null && ts.pubEaaProviders().lotl() != null) {
            var p = ts.pubEaaProviders().lotl();
            addJob(VerificationContextTO.PubEAA.name(), null, p, cacheDir, executor);
            addJob(VerificationContextTO.PubEAAStatus.name(), null, p, cacheDir, executor);
        }
        if (ts.eaaProviders() != null) {
            for (var eaa : ts.eaaProviders()) {
                if (eaa.lotl() != null) {
                    addJob(VerificationContextTO.EAA.name(), eaa.useCase(), eaa.lotl(), cacheDir, executor);
                    addJob(VerificationContextTO.EAAStatus.name(), eaa.useCase(), eaa.lotl(), cacheDir, executor);
                }
            }
        }
        if (ts.wrpacProviders() != null && ts.wrpacProviders().lotl() != null) {
            addJob(VerificationContextTO.WalletRelyingPartyAccessCertificate.name(), null, ts.wrpacProviders().lotl(), cacheDir, executor);
        }
        if (ts.wrprcProviders() != null && ts.wrprcProviders().lotl() != null) {
            addJob(VerificationContextTO.WalletRelyingPartyRegistrationCertificate.name(), null, ts.wrprcProviders().lotl(), cacheDir, executor);
        }
    }

    private void addJob(String contextName, String useCase,
                        TrustValidatorProperties.LoTLProperties lotlProps,
                        java.io.File cacheDir, ExecutorService executor) {
        var key = contextName + (useCase != null ? ":" + useCase : "");
        var source = buildLotlSource(lotlProps);
        var certSource = new TrustedListsCertificateSource();
        var job = new TLValidationJob();
        job.setListOfTrustedListSources(source);
        job.setOfflineDataLoader(buildOfflineLoader(cacheDir));
        job.setOnlineDataLoader(buildOnlineLoader(cacheDir));
        job.setExecutorService(executor);
        job.setTrustedListCertificateSource(certSource);
        validationJobs.put(key, job);
        lotlCertSources.put(key, certSource);
    }

    private LOTLSource buildLotlSource(TrustValidatorProperties.LoTLProperties p) {
        var source = new LOTLSource();
        source.setUrl(p.location().toExternalForm());
        source.setTrustAnchorValidityPredicate(new GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate());
        source.setTLVersions(List.of(5, 6));
        if (p.issuanceService() != null) {
            var svcUri = p.issuanceService().toString();
            source.setTrustServicePredicate(si ->
                    svcUri.equals(si.getServiceInformation().getServiceTypeIdentifier())
            );
        }
        if (p.signatureVerification() != null) {
            try (var is = p.signatureVerification().location().getInputStream()) {
                source.setCertificateSource(new KeyStoreCertificateSource(
                        is,
                        p.signatureVerification().keyStoreType(),
                        (p.signatureVerification().password() != null
                                ? p.signatureVerification().password() : "").toCharArray()
                ));
            } catch (IOException e) {
                throw new IllegalStateException("Failed to load LoTL signature verification KeyStore", e);
            }
        }
        return source;
    }

    private FileCacheDataLoader buildOfflineLoader(java.io.File cacheDir) {
        var loader = new FileCacheDataLoader();
        loader.setFileCacheDirectory(cacheDir);
        // No backing DataLoader — reads only from existing cache files
        return loader;
    }

    private FileCacheDataLoader buildOnlineLoader(java.io.File cacheDir) {
        var loader = new FileCacheDataLoader();
        loader.setFileCacheDirectory(cacheDir);
        loader.setCacheExpirationTime(24 * 60 * 60 * 1000L); // 24h
        loader.setDataLoader(new CommonsDataLoader());
        return loader;
    }

    // ---------------------------------------------------------------------------
    // Chain validation helpers
    // ---------------------------------------------------------------------------

    private Optional<X509Certificate> validateChain(List<X509Certificate> chain,
                                                     TrustedListsCertificateSource certSource) {
        var anchors = new HashSet<TrustAnchor>();
        for (CertificateToken token : certSource.getCertificates()) {
            anchors.add(new TrustAnchor(token.getCertificate(), null));
        }
        if (anchors.isEmpty()) {
            log.debug("LoTL cert source has no trust anchors yet — skipping PKIX validation");
            return Optional.empty();
        }
        log.debug("Validating chain against LoTL ({} anchors)", anchors.size());
        return validatePkix(chain, anchors);
    }

    private Optional<X509Certificate> validateWithKeyStore(List<X509Certificate> chain, KeyStore keyStore) {
        try {
            var anchors = new HashSet<TrustAnchor>();
            var aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                var alias = aliases.nextElement();
                if (keyStore.isCertificateEntry(alias)) {
                    anchors.add(new TrustAnchor((X509Certificate) keyStore.getCertificate(alias), null));
                }
            }
            log.debug("Validating chain against KeyStore ({} anchors)", anchors.size());
            return validatePkix(chain, anchors);
        } catch (KeyStoreException e) {
            log.warn("KeyStore validation error: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private Optional<X509Certificate> validatePkix(List<X509Certificate> chain, Set<TrustAnchor> anchors) {
        try {
            var certFactory = CertificateFactory.getInstance("X.509");
            var certPath = certFactory.generateCertPath(chain);
            var params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            var validator = CertPathValidator.getInstance("PKIX");
            var result = (PKIXCertPathValidatorResult) validator.validate(certPath, params);
            return Optional.ofNullable(result.getTrustAnchor().getTrustedCert());
        } catch (Exception e) {
            log.debug("PKIX validation failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    static String contextKey(VerificationContextTO ctx, String useCase) {
        return switch (ctx) {
            case EAA, EAAStatus, Custom -> ctx.name() + ":" + useCase;
            default -> ctx.name();
        };
    }

    private KeyStore loadKeyStore(TrustValidatorProperties.KeyStoreProperties config)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        var ks = KeyStore.getInstance(config.keyStoreType());
        try (var is = config.location().getInputStream()) {
            ks.load(is, (config.password() != null ? config.password() : "").toCharArray());
        }
        return ks;
    }

    private boolean hasLoteConfig() {
        var ts = properties.trustSources();
        if (ts == null) return false;
        return (ts.walletProviders() != null && ts.walletProviders().lote() != null)
                || (ts.pidProviders() != null && ts.pidProviders().lote() != null)
                || (ts.qeaaProviders() != null && ts.qeaaProviders().lote() != null)
                || (ts.pubEaaProviders() != null && ts.pubEaaProviders().lote() != null)
                || (ts.wrpacProviders() != null && ts.wrpacProviders().lote() != null)
                || (ts.wrprcProviders() != null && ts.wrprcProviders().lote() != null)
                || (ts.eaaProviders() != null && ts.eaaProviders().stream().anyMatch(e -> e.lote() != null));
    }
}

package dev.kmandalas.qtspmock.service;

import dev.kmandalas.qtspmock.repository.CredentialRepository;
import dev.kmandalas.qtspmock.repository.CredentialRepository.PersistedCredential;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages a stable QTSP CA (loaded via Spring Boot SSL Bundle) and per-user signing
 * credentials persisted in PostgreSQL. An in-memory cache avoids repeated key deserialization.
 */
@Service
public class KeyManagementService {

    private static final Logger logger = LoggerFactory.getLogger(KeyManagementService.class);
    private static final String DEFAULT_USER_ID = "default-user";

    private final ECPrivateKey caPrivateKey;
    private final X509Certificate caCertificate;
    private final CredentialRepository credentialRepository;
    private final ConcurrentHashMap<String, ManagedCredential> cache = new ConcurrentHashMap<>();

    public KeyManagementService(SslBundles sslBundles, CredentialRepository credentialRepository) throws Exception {
        this.credentialRepository = credentialRepository;

        SslBundle bundle = sslBundles.getBundle("qtsp-ca");
        KeyStore keyStore = bundle.getStores().getKeyStore();

        String alias = keyStore.aliases().nextElement();
        this.caPrivateKey = (ECPrivateKey) keyStore.getKey(alias, null);
        this.caCertificate = (X509Certificate) keyStore.getCertificate(alias);

        logger.info("🏛️ Loaded QTSP CA via SSL Bundle: {}", caCertificate.getSubjectX500Principal().getName());
    }

    /**
     * Returns credentials for a given user, creating them lazily if none exist.
     */
    public List<ManagedCredential> getOrCreateCredentials(String userId) {
        String resolvedUserId = (userId == null || userId.isBlank()) ? DEFAULT_USER_ID : userId;

        List<PersistedCredential> persisted = credentialRepository.findByUserId(resolvedUserId);
        if (!persisted.isEmpty()) {
            return persisted.stream()
                    .map(p -> getCredential(p.credentialId()))
                    .filter(Objects::nonNull)
                    .toList();
        }

        // Lazy generation for new user
        try {
            String credentialId = UUID.randomUUID().toString();
            ManagedCredential credential = generateCredential(credentialId, resolvedUserId);

            credentialRepository.save(new PersistedCredential(
                    credentialId,
                    resolvedUserId,
                    credential.privateKey().getEncoded(),
                    credential.publicKey().getEncoded(),
                    credential.userCertificate().getEncoded(),
                    Instant.now()
            ));

            cache.put(credentialId, credential);
            logger.info("🔑 Generated new credential for user '{}': {}", resolvedUserId, credentialId);
            return List.of(credential);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate QTSP credential for user: " + resolvedUserId, e);
        }
    }

    public ManagedCredential getCredential(String credentialId) {
        ManagedCredential cached = cache.get(credentialId);
        if (cached != null) {
            return cached;
        }

        // DB fallback
        return credentialRepository.findByCredentialId(credentialId)
                .map(this::reconstruct)
                .orElse(null);
    }

    public List<String> listCredentialIds(String userId) {
        String resolvedUserId = (userId == null || userId.isBlank()) ? DEFAULT_USER_ID : userId;
        return getOrCreateCredentials(resolvedUserId).stream()
                .map(ManagedCredential::credentialId)
                .toList();
    }

    /**
     * Returns all credentials across all users (for dashboard).
     */
    public List<ManagedCredential> listAllCredentials() {
        return credentialRepository.findAll().stream()
                .map(p -> getCredential(p.credentialId()))
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Returns the full certificate chain as Base64-encoded DER: [user cert, CA cert].
     */
    public List<String> getCertificateChainBase64(ManagedCredential credential) {
        try {
            return List.of(
                    Base64.getEncoder().encodeToString(credential.userCertificate().getEncoded()),
                    Base64.getEncoder().encodeToString(credential.caCertificate().getEncoded())
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode certificate chain", e);
        }
    }

    private ManagedCredential generateCredential(String credentialId, String userId) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair userKeyPair = keyGen.generateKeyPair();

        X500Name issuerDN = X500Name.getInstance(caCertificate.getSubjectX500Principal().getEncoded());
        X500Name subjectDN = new X500Name("CN=" + userId + " Signing Key, O=K-QTSP Mock, C=GR");
        Instant now = Instant.now();

        ContentSigner caSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(caPrivateKey);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerDN,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subjectDN,
                userKeyPair.getPublic()
        );

        X509CertificateHolder certHolder = certBuilder.build(caSigner);
        X509Certificate userCertificate = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new ManagedCredential(credentialId, userId, userKeyPair.getPrivate(), userKeyPair.getPublic(),
                userCertificate, caCertificate);
    }

    private ManagedCredential reconstruct(PersistedCredential persisted) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(persisted.privateKey()));
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(persisted.publicKey()));
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(persisted.certificate()));

            var credential = new ManagedCredential(persisted.credentialId(), persisted.userId(),
                    pk, pub, cert, caCertificate);
            cache.put(persisted.credentialId(), credential);
            return credential;
        } catch (Exception e) {
            logger.error("❌ Failed to reconstruct credential {}: {}", persisted.credentialId(), e.getMessage());
            return null;
        }
    }

    public record ManagedCredential(
            String credentialId,
            String userId,
            PrivateKey privateKey,
            PublicKey publicKey,
            X509Certificate userCertificate,
            X509Certificate caCertificate
    ) {}

}

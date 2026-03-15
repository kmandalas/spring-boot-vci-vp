package dev.kmandalas.qtspmock.service;

import jakarta.annotation.PostConstruct;
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

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages a stable QTSP CA (loaded via Spring Boot SSL Bundle) and dynamically generates
 * user signing key pairs with certificates signed by the CA.
 * This mirrors how a real QTSP operates: stable CA, per-user signing keys in HSM.
 */
@Service
public class KeyManagementService {

    private static final Logger logger = LoggerFactory.getLogger(KeyManagementService.class);

    private final ECPrivateKey caPrivateKey;
    private final X509Certificate caCertificate;
    private final ConcurrentHashMap<String, ManagedCredential> credentials = new ConcurrentHashMap<>();

    public KeyManagementService(SslBundles sslBundles) throws Exception {
        SslBundle bundle = sslBundles.getBundle("qtsp-ca");
        KeyStore keyStore = bundle.getStores().getKeyStore();

        String alias = keyStore.aliases().nextElement();
        this.caPrivateKey = (ECPrivateKey) keyStore.getKey(alias, null);
        this.caCertificate = (X509Certificate) keyStore.getCertificate(alias);

        logger.info("🏛️ Loaded QTSP CA via SSL Bundle: {}", caCertificate.getSubjectX500Principal().getName());
    }

    @PostConstruct
    public void init() {
        try {
            String credentialId = UUID.randomUUID().toString();
            ManagedCredential credential = generateCredential(credentialId);
            credentials.put(credentialId, credential);
            logger.info("🔑 Pre-generated user signing credential: {}", credentialId);
        } catch (Exception e) {
            throw new RuntimeException("Failed to pre-generate QTSP credential", e);
        }
    }

    private ManagedCredential generateCredential(String credentialId) throws Exception {
        // Generate fresh EC P-256 key pair for the user
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair userKeyPair = keyGen.generateKeyPair();

        // Issue certificate signed by the QTSP CA
        X500Name issuerDN = X500Name.getInstance(caCertificate.getSubjectX500Principal().getEncoded());
        X500Name subjectDN = new X500Name("CN=Wallet User Signing Key, O=K-QTSP Mock, C=GR");
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

        return new ManagedCredential(credentialId, userKeyPair.getPrivate(), userKeyPair.getPublic(),
                userCertificate, caCertificate);
    }

    public ManagedCredential getCredential(String credentialId) {
        return credentials.get(credentialId);
    }

    public List<String> listCredentialIds() {
        return List.copyOf(credentials.keySet());
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

    public record ManagedCredential(
            String credentialId,
            PrivateKey privateKey,
            PublicKey publicKey,
            X509Certificate userCertificate,
            X509Certificate caCertificate
    ) {}

}

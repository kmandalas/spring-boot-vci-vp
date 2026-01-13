package com.example.walletprovider.service;

import com.example.walletprovider.model.KeyAttestationData;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

@Service
public class KeyAttestationService {

    private static final Logger logger = LoggerFactory.getLogger(KeyAttestationService.class);

    private static final String KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    // Android Key Attestation security levels (ASN.1 enum values)
    private static final int SECURITY_LEVEL_TEE = 1;
    private static final int SECURITY_LEVEL_STRONGBOX = 2;
    // Note: 0 = SOFTWARE, handled by default case

    @Value("classpath:/google_hardware_attestation_root.pem")
    private Resource googleRootCaResource;

    @Value("${wp.attestation.skip-chain-validation:false}")
    private boolean skipChainValidation;

    private Set<TrustAnchor> trustAnchors;

    @PostConstruct
    public void init() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        trustAnchors = loadGoogleRootCertificates();
        logger.info("Loaded {} Google Hardware Attestation root certificate(s)", trustAnchors.size());
        if (skipChainValidation) {
            logger.warn("⚠️ Key attestation chain validation is DISABLED - for development only!");
        }
    }

    public KeyAttestationData validateAndExtract(List<String> base64CertChain)
            throws CertificateException, CertPathValidatorException {

        if (base64CertChain == null || base64CertChain.isEmpty()) {
            throw new CertificateException("Certificate chain is empty");
        }

        List<X509Certificate> certChain = parseCertificateChain(base64CertChain);
        logger.debug("Parsed {} certificates from chain", certChain.size());

        if (skipChainValidation) {
            logger.warn("⚠️Skipping certificate chain validation (development mode)");
        } else {
            validateChainToGoogleRoot(certChain);
            logger.debug("Certificate chain validated successfully");
        }

        X509Certificate leafCert = certChain.getFirst();
        return parseKeyAttestationExtension(leafCert);
    }

    private List<X509Certificate> parseCertificateChain(List<String> base64Certs)
            throws CertificateException {

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();

        for (String base64Cert : base64Certs) {
            byte[] certBytes = Base64.getDecoder().decode(base64Cert);
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(certBytes));
            certs.add(cert);
        }

        return certs;
    }

    private void validateChainToGoogleRoot(List<X509Certificate> certChain)
            throws CertificateException, CertPathValidatorException {

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certFactory.generateCertPath(certChain);

            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);

        } catch (Exception e) {
            if (e instanceof CertPathValidatorException) {
                throw (CertPathValidatorException) e;
            }
            throw new CertificateException("Failed to validate certificate chain", e);
        }
    }

    private KeyAttestationData parseKeyAttestationExtension(X509Certificate leafCert)
            throws CertificateException {

        byte[] extensionValue = leafCert.getExtensionValue(KEY_ATTESTATION_OID);
        if (extensionValue == null) {
            throw new CertificateException("Key attestation extension not found in certificate");
        }

        try {
            ASN1OctetString octetString = ASN1OctetString.getInstance(extensionValue);
            ASN1Sequence attestationSeq = ASN1Sequence.getInstance(octetString.getOctets());

            int attestationVersion = ((ASN1Integer) attestationSeq.getObjectAt(0)).intValueExact();
            int attestationSecurityLevel = ((ASN1Enumerated) attestationSeq.getObjectAt(1)).intValueExact();
            byte[] attestationChallenge = ((ASN1OctetString) attestationSeq.getObjectAt(4)).getOctets();

            String wscdType = mapSecurityLevelToWscdType(attestationSecurityLevel);
            String wscdSecurityLevel = mapSecurityLevelToString(attestationSecurityLevel);

            PublicKey walletPublicKey = leafCert.getPublicKey();

            logger.info("Key attestation parsed: version={}, securityLevel={}, wscdType={}",
                    attestationVersion, attestationSecurityLevel, wscdType);

            return new KeyAttestationData(
                    walletPublicKey,
                    wscdType,
                    wscdSecurityLevel,
                    attestationVersion,
                    attestationChallenge
            );

        } catch (Exception e) {
            throw new CertificateException("Failed to parse key attestation extension", e);
        }
    }

    private String mapSecurityLevelToWscdType(int level) {
        return switch (level) {
            case SECURITY_LEVEL_STRONGBOX -> KeyAttestationData.WSCD_TYPE_STRONGBOX;
            case SECURITY_LEVEL_TEE -> KeyAttestationData.WSCD_TYPE_TEE;
            default -> KeyAttestationData.WSCD_TYPE_SOFTWARE;
        };
    }

    private String mapSecurityLevelToString(int level) {
        return switch (level) {
            case SECURITY_LEVEL_STRONGBOX, SECURITY_LEVEL_TEE -> KeyAttestationData.SECURITY_LEVEL_HARDWARE;
            default -> KeyAttestationData.SECURITY_LEVEL_SOFTWARE;
        };
    }

    private Set<TrustAnchor> loadGoogleRootCertificates() throws Exception {
        Set<TrustAnchor> anchors = new HashSet<>();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        try (InputStream is = googleRootCaResource.getInputStream()) {
            Collection<? extends Certificate> certs = certFactory.generateCertificates(is);
            for (Certificate cert : certs) {
                if (cert instanceof X509Certificate x509Cert) {
                    anchors.add(new TrustAnchor(x509Cert, null));
                    logger.debug("Loaded root certificate: {}", x509Cert.getSubjectX500Principal());
                }
            }
        }

        if (anchors.isEmpty()) {
            throw new IllegalStateException("No root certificates loaded from resource");
        }

        return anchors;
    }

}

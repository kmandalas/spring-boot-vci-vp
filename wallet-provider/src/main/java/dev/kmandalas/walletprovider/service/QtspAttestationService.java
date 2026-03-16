package dev.kmandalas.walletprovider.service;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import dev.kmandalas.walletprovider.client.TrustValidatorClient;
import dev.kmandalas.walletprovider.config.QtspProperties;
import dev.kmandalas.walletprovider.model.KeyAttestationData;
import dev.kmandalas.walletprovider.model.WuaCredentialRequest.QtspCredentialInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Validates QTSP credential info from the CSC API credentials/info response.
 * Verifies SCAL level, extracts the public key from the certificate, and checks
 * it matches the proof JWT's key. Optionally validates the QTSP certificate chain
 * via the trust-validator service.
 */
@Service
public class QtspAttestationService {

    private static final Logger logger = LoggerFactory.getLogger(QtspAttestationService.class);

    private final TrustValidatorClient trustValidatorClient;
    private final QtspProperties qtspProperties;

    public QtspAttestationService(TrustValidatorClient trustValidatorClient, QtspProperties qtspProperties) {
        this.trustValidatorClient = trustValidatorClient;
        this.qtspProperties = qtspProperties;
    }

    /**
     * Validates QTSP credential info and returns KeyAttestationData.
     *
     * @param credentialInfo the CSC credentials/info response sent by the wallet
     * @param proofJwk       the JWK from the proof JWT header (must match the QTSP-managed key)
     * @return KeyAttestationData with wscdType = "remote_qscd"
     */
    public KeyAttestationData validateAndExtract(QtspCredentialInfo credentialInfo, JWK proofJwk)
            throws CertificateException {

        if (credentialInfo == null) {
            throw new CertificateException("QTSP credential info is required");
        }

        // 1. Verify SCAL level — SCAL=2 means key resides in hardware (QSCD)
        if (!"2".equals(credentialInfo.scal())) {
            throw new CertificateException("QTSP credential SCAL must be 2 (hardware QSCD), got: " +
                    credentialInfo.scal());
        }
        logger.info("✅ QTSP SCAL level verified: {}", credentialInfo.scal());

        // 2. Verify key status is enabled
        if (credentialInfo.key() == null || !"enabled".equals(credentialInfo.key().status())) {
            throw new CertificateException("QTSP credential key is not enabled");
        }

        // 3. Extract public key from the certificate chain
        if (credentialInfo.cert() == null || credentialInfo.cert().certificates() == null
                || credentialInfo.cert().certificates().isEmpty()) {
            throw new CertificateException("QTSP credential must include at least one certificate");
        }

        List<String> certChain = credentialInfo.cert().certificates();
        String certBase64 = certChain.getFirst();
        X509Certificate certificate = parseCertificate(certBase64);
        ECPublicKey qtspPublicKey = extractEcPublicKey(certificate);

        // 4. Validate QTSP certificate chain via trust-validator (if enabled)
        validateCertificateChainTrust(certChain);

        // 5. Verify that the QTSP-managed public key matches the proof JWT's JWK
        verifyKeyMatch(proofJwk, qtspPublicKey);
        logger.info("✅ QTSP public key matches proof JWT key");

        return new KeyAttestationData(
                qtspPublicKey,
                KeyAttestationData.WSCD_TYPE_REMOTE_QSCD,
                KeyAttestationData.SECURITY_LEVEL_HARDWARE,
                0, // attestation version not applicable for QTSP
                new byte[0] // attestation challenge not applicable for QTSP
        );
    }

    private void validateCertificateChainTrust(List<String> certChain) throws CertificateException {
        if (!qtspProperties.isTrustValidatorEnabled()) {
            logger.debug("🔗 QTSP certificate chain trust validation skipped (trust-validator not enabled)");
            return;
        }

        Optional<String> trustAnchor = trustValidatorClient.isTrusted(
                certChain, "QTSPSigningCertificate");

        if (trustAnchor.isEmpty()) {
            throw new CertificateException(
                    "QTSP certificate chain not trusted by trust-validator");
        }
        logger.info("✅ QTSP certificate chain validated by trust-validator");
    }

    private X509Certificate parseCertificate(String base64Cert) throws CertificateException {
        byte[] certBytes = Base64.getDecoder().decode(base64Cert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    private ECPublicKey extractEcPublicKey(X509Certificate certificate) throws CertificateException {
        if (certificate.getPublicKey() instanceof ECPublicKey ecPublicKey) {
            return ecPublicKey;
        }
        throw new CertificateException("QTSP certificate does not contain an EC public key");
    }

    private void verifyKeyMatch(JWK proofJwk, ECPublicKey qtspKey) throws CertificateException {
        try {
            if (proofJwk.getKeyType() != KeyType.EC) {
                throw new CertificateException("Proof key must be EC for QTSP attestation");
            }
            ECPublicKey proofKey = ((ECKey) proofJwk).toECPublicKey();
            if (!proofKey.getW().equals(qtspKey.getW())) {
                throw new CertificateException("Proof key does not match QTSP-managed key");
            }
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Error comparing proof key with QTSP key", e);
        }
    }

}

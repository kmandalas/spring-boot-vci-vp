package dev.kmandalas.qtspmock.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

@Service
public class SigningService {

    private static final Logger logger = LoggerFactory.getLogger(SigningService.class);

    /**
     * Signs a SHA-256 hash with the managed EC P-256 private key.
     * Returns raw EC signature (DER-encoded) as Base64.
     */
    public String signHash(PrivateKey privateKey, byte[] hash) {
        try {
            // NONEwithECDSA: the hash is pre-computed, we just sign it directly
            Signature signature = Signature.getInstance("NONEwithECDSA");
            signature.initSign(privateKey);
            signature.update(hash);
            byte[] sig = signature.sign();

            String base64Sig = Base64.getEncoder().encodeToString(sig);
            logger.info("✍️ Signed hash, signature length: {} bytes", sig.length);
            return base64Sig;
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign hash", e);
        }
    }

}

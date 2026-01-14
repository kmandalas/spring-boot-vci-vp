package com.example.issuer.service;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;
import java.util.zip.Inflater;

/**
 * Service for validating WUA revocation status via Token Status List.
 * Implements IETF draft-ietf-oauth-status-list specification.
 */
@Service
public class StatusListValidationService {

    private static final Logger logger = LoggerFactory.getLogger(StatusListValidationService.class);

    private final RestClient restClient;

    public StatusListValidationService(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder.build();
    }

    /**
     * Check if a WUA is revoked by fetching and validating the status list.
     *
     * @param statusListUri The URI of the status list token endpoint
     * @param idx The index in the status list bitstring
     * @return true if revoked, false if valid
     */
    public boolean isRevoked(String statusListUri, int idx) {
        try {
            // 1. Fetch Status List Token
            String statusListJwt = fetchStatusListToken(statusListUri);
            if (statusListJwt == null) {
                logger.warn("⚠️Failed to fetch status list from {}", statusListUri);
                return true; // Fail-safe: treat as revoked if can't fetch
            }

            // 2. Parse and verify JWT signature (using x5c from header)
            SignedJWT signedJWT = SignedJWT.parse(statusListJwt);
            if (!verifyStatusListSignature(signedJWT)) {
                logger.warn("⚠️Status list signature verification failed");
                return true; // Fail-safe: treat as revoked if can't verify
            }

            // 3. Extract status_list claim
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            @SuppressWarnings("unchecked")
            Map<String, Object> statusList = (Map<String, Object>) claims.getClaim("status_list");
            if (statusList == null) {
                logger.warn("⚠️No status_list claim in token");
                return true;
            }

            int bits = ((Number) statusList.get("bits")).intValue();
            String lst = (String) statusList.get("lst");

            // 4. Decompress bitstring
            byte[] compressed = java.util.Base64.getUrlDecoder().decode(lst);
            byte[] bitstring = decompress(compressed);

            // 5. Extract status value at index
            int statusValue = getBitValue(bitstring, idx, bits);

            logger.debug("Status list check: uri={}, idx={}, bits={}, value={}",
                    statusListUri, idx, bits, statusValue);

            return statusValue == 1; // 1 = revoked

        } catch (Exception e) {
            logger.error("❌Error checking status list", e);
            return true; // Fail-safe: treat as revoked on error
        }
    }

    /**
     * Fetch the status list token from the Wallet Provider.
     */
    private String fetchStatusListToken(String statusListUri) {
        try {
            return restClient.get()
                    .uri(statusListUri)
                    .accept(MediaType.parseMediaType("application/statuslist+jwt"))
                    .retrieve()
                    .body(String.class);
        } catch (Exception e) {
            logger.error("❌Failed to fetch status list from {}", statusListUri, e);
            return null;
        }
    }

    /**
     * Verify the status list JWT signature using x5c certificate chain.
     */
    private boolean verifyStatusListSignature(SignedJWT signedJWT) {
        try {
            List<Base64> x5cChain = signedJWT.getHeader().getX509CertChain();
            if (x5cChain == null || x5cChain.isEmpty()) {
                logger.warn("⚠️No x5c certificate chain in status list token");
                return false;
            }

            // Parse leaf certificate (first in chain)
            byte[] certBytes = x5cChain.get(0).decode();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(certBytes));

            // Extract EC public key and verify
            ECPublicKey ecPublicKey = (ECPublicKey) certificate.getPublicKey();
            ECKey ecKey = new ECKey.Builder(Curve.P_256, ecPublicKey).build();
            JWSVerifier verifier = new ECDSAVerifier(ecKey);

            return signedJWT.verify(verifier);

        } catch (Exception e) {
            logger.error("❌Error verifying status list signature", e);
            return false;
        }
    }

    /**
     * Decompress bitstring using DEFLATE/ZLIB.
     */
    private byte[] decompress(byte[] compressed) throws Exception {
        Inflater inflater = new Inflater();
        inflater.setInput(compressed);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(compressed.length * 8);
        byte[] buffer = new byte[1024];

        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            if (count == 0 && inflater.needsInput()) {
                break;
            }
            outputStream.write(buffer, 0, count);
        }

        inflater.end();
        return outputStream.toByteArray();
    }

    /**
     * Extract the status value at the given index in the bitstring.
     * Uses LSB-first packing per IETF draft-ietf-oauth-status-list spec.
     */
    private int getBitValue(byte[] bitstring, int idx, int bits) {
        int bitPosition = idx * bits;
        int byteIndex = bitPosition / 8;
        int bitOffset = bitPosition % 8;

        if (byteIndex >= bitstring.length) {
            logger.warn("⚠️Index {} out of bounds for bitstring of size {}", idx, bitstring.length);
            return 1; // Treat out-of-bounds as revoked
        }

        // Extract value (LSB-first packing per spec)
        int mask = (1 << bits) - 1;
        return (bitstring[byteIndex] >> bitOffset) & mask;
    }

}

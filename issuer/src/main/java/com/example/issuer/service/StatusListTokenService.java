package com.example.issuer.service;

import com.example.issuer.model.CredentialStatusEntry;
import com.example.issuer.model.StatusList;
import com.example.issuer.repository.CredentialStatusRepository;
import com.example.issuer.repository.StatusListRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

@Service
public class StatusListTokenService {

    private static final Logger logger = LoggerFactory.getLogger(StatusListTokenService.class);

    private final StatusListRepository statusListRepository;
    private final CredentialStatusRepository credentialStatusRepository;
    private final IssuerSigningService issuerSigningService;

    public StatusListTokenService(StatusListRepository statusListRepository,
                                   CredentialStatusRepository credentialStatusRepository,
                                   IssuerSigningService issuerSigningService) {
        this.statusListRepository = statusListRepository;
        this.credentialStatusRepository = credentialStatusRepository;
        this.issuerSigningService = issuerSigningService;
    }

    /**
     * Generate a signed Status List Token JWT for the given list ID.
     */
    public String generateStatusListToken(String listId) {
        StatusList statusList = statusListRepository.findById(listId)
                .orElseThrow(() -> new IllegalArgumentException("Status list not found: " + listId));

        List<CredentialStatusEntry> entries = credentialStatusRepository.findByStatusListId(listId);

        // Build bitstring
        byte[] bitstring = createBitstring(statusList, entries);

        // Compress with DEFLATE
        byte[] compressed = compress(bitstring);

        // Base64url encode
        String lst = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(compressed);

        // Build and sign JWT
        return buildStatusListJwt(statusList, lst);
    }

    /**
     * Create the bitstring with LSB-first packing per IETF spec.
     */
    byte[] createBitstring(StatusList statusList, List<CredentialStatusEntry> entries) {
        byte[] bitstring = new byte[statusList.getByteSize()];

        for (CredentialStatusEntry entry : entries) {
            if ("REVOKED".equals(entry.status())) {
                setBitValue(bitstring, entry.statusListIdx(), statusList.bits(), 1);
            }
        }

        return bitstring;
    }

    /**
     * Set a value at the given index in the bitstring (LSB-first packing).
     */
    void setBitValue(byte[] bitstring, int idx, int bits, int value) {
        int bitPosition = idx * bits;
        int byteIndex = bitPosition / 8;
        int bitOffset = bitPosition % 8;

        if (byteIndex < bitstring.length) {
            bitstring[byteIndex] |= (byte) (value << bitOffset);
        }
    }

    /**
     * Compress using DEFLATE with best compression.
     */
    byte[] compress(byte[] data) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();

        byte[] buffer = new byte[data.length * 2];
        int compressedSize = deflater.deflate(buffer);
        deflater.end();

        byte[] result = new byte[compressedSize];
        System.arraycopy(buffer, 0, result, 0, compressedSize);
        return result;
    }

    /**
     * Build and sign the Status List JWT.
     */
    private String buildStatusListJwt(StatusList statusList, String lst) {
        try {
            JWK signingKey = issuerSigningService.getSigningKey();
            List<Base64> x5cChain = issuerSigningService.getX5cChain();

            JWSAlgorithm alg = JWSAlgorithm.parse(signingKey.getAlgorithm().getName());

            JWSHeader header = new JWSHeader.Builder(alg)
                    .type(new JOSEObjectType("statuslist+jwt"))
                    .x509CertChain(x5cChain)
                    .build();

            long now = Instant.now().getEpochSecond();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issueTime(java.util.Date.from(Instant.ofEpochSecond(now)))
                    .claim("status_list", Map.of(
                            "bits", statusList.bits(),
                            "lst", lst
                    ))
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims);
            JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(signingKey);
            jwt.sign(signer);

            return jwt.serialize();

        } catch (Exception e) {
            logger.error("Failed to generate status list token", e);
            throw new RuntimeException("Failed to generate status list token", e);
        }
    }
}

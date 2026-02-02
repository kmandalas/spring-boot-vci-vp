package com.example.walletprovider.service;

import com.example.walletprovider.config.WpMetadataConfig;
import com.example.walletprovider.model.StatusList;
import com.example.walletprovider.model.WalletUnitAttestation;
import com.example.walletprovider.repository.StatusListRepository;
import com.example.walletprovider.repository.WuaRepository;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

/**
 * Service for generating Token Status List JWTs per IETF draft-ietf-oauth-status-list.
 * Creates compressed bitstring representation of credential revocation status.
 */
@Service
public class StatusListTokenService {

    private static final Logger logger = LoggerFactory.getLogger(StatusListTokenService.class);

    // TTL for status list tokens (1 hour)
    private static final long STATUS_LIST_TTL_SECONDS = 3600;

    private final StatusListRepository statusListRepository;
    private final WuaRepository wuaRepository;
    private final WpSigningService wpSigningService;
    private final WpMetadataConfig wpMetadataConfig;

    public StatusListTokenService(StatusListRepository statusListRepository,
                                   WuaRepository wuaRepository,
                                   WpSigningService wpSigningService,
                                   WpMetadataConfig wpMetadataConfig) {
        this.statusListRepository = statusListRepository;
        this.wuaRepository = wuaRepository;
        this.wpSigningService = wpSigningService;
        this.wpMetadataConfig = wpMetadataConfig;
    }

    /**
     * Generate a Status List Token JWT for the given status list.
     *
     * @param listId The status list ID
     * @return Signed JWT string with type "statuslist+jwt"
     */
    public String generateStatusListToken(String listId) throws JOSEException {
        StatusList statusList = statusListRepository.findById(listId)
            .orElseThrow(() -> new IllegalArgumentException("Status list not found: " + listId));

        List<WalletUnitAttestation> wuas = wuaRepository.findByStatusListId(listId);

        // Create bitstring
        byte[] bitstring = createBitstring(statusList, wuas);

        // Compress with DEFLATE/ZLIB
        byte[] compressed = compress(bitstring);
        String lst = Base64.getUrlEncoder().withoutPadding().encodeToString(compressed);

        logger.debug("Status list {}: {} WUAs, {} bytes uncompressed, {} bytes compressed",
            listId, wuas.size(), bitstring.length, compressed.length);

        // Build and sign JWT
        return buildStatusListJwt(listId, statusList.bits(), lst);
    }

    /**
     * Create bitstring from WUA statuses.
     * Each bit represents the revocation status: 0=valid, 1=revoked.
     * Bits are packed LSB-first per IETF spec.
     */
    private byte[] createBitstring(StatusList statusList, List<WalletUnitAttestation> wuas) {
        byte[] bitstring = new byte[statusList.getByteSize()];

        for (WalletUnitAttestation wua : wuas) {
            if (wua.statusListIdx() == null) {
                continue;
            }

            int idx = wua.statusListIdx();
            int statusValue = WalletUnitAttestation.STATUS_REVOKED.equals(wua.status()) ? 1 : 0;
            setBitValue(bitstring, idx, statusList.bits(), statusValue);
        }

        return bitstring;
    }

    /**
     * Set the status value at the given index in the bitstring.
     * Uses LSB-first packing per IETF draft-ietf-oauth-status-list spec.
     */
    private void setBitValue(byte[] bitstring, int idx, int bits, int value) {
        int bitPosition = idx * bits;
        int byteIndex = bitPosition / 8;
        int bitOffset = bitPosition % 8;

        if (byteIndex >= bitstring.length) {
            logger.warn("Index {} out of bounds for bitstring of size {}", idx, bitstring.length);
            return;
        }

        // Clear existing bits and set new value (LSB-first)
        int mask = ((1 << bits) - 1) << bitOffset;
        bitstring[byteIndex] = (byte) ((bitstring[byteIndex] & ~mask) | ((value << bitOffset) & mask));
    }

    /**
     * Compress bitstring using DEFLATE with ZLIB wrapper.
     */
    private byte[] compress(byte[] data) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];

        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            outputStream.write(buffer, 0, count);
        }

        deflater.end();
        return outputStream.toByteArray();
    }

    /**
     * Build and sign the Status List Token JWT.
     */
    private String buildStatusListJwt(String listId, int bits, String lst) throws JOSEException {
        Instant now = Instant.now();
        Instant exp = now.plus(STATUS_LIST_TTL_SECONDS, ChronoUnit.SECONDS);

        String statusListUri = wpMetadataConfig.getEndpoints().getStatusList() + "/" + listId;

        // Build header with statuslist+jwt type and x5c
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(wpSigningService.getSigningKey().getKeyID())
            .type(new JOSEObjectType("statuslist+jwt"))
            .x509CertChain(wpSigningService.getX5cChain())
            .build();

        // Build claims per IETF spec
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer(wpMetadataConfig.getClaims().getIss())
            .subject(statusListUri)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(exp))
            .claim("ttl", STATUS_LIST_TTL_SECONDS)
            .claim("status_list", Map.of(
                "bits", bits,
                "lst", lst
            ))
            .build();

        // Sign JWT
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(new ECDSASigner(wpSigningService.getSigningKey()));

        logger.debug("Generated status list token for list {}", listId);
        return signedJWT.serialize();
    }

}

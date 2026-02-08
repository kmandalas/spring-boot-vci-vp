package com.example.issuer.service.credential;

import com.authlete.cose.COSEEC2Key;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSEKey;
import com.authlete.mdoc.IssuerSigned;
import com.authlete.mdoc.IssuerSignedBuilder;
import com.authlete.mdoc.ValidityInfo;
import com.example.issuer.service.AuthSourceHelper;
import com.example.issuer.service.IssuerSigningService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for generating mDoc (ISO/IEC 18013-5:2021) credentials
 * using Authlete's CBOR library utilities.
 */
@Service
public class MDocIssuerService {

    private static final String DOC_TYPE = "eu.europa.ec.eudi.pda1.1";
    private static final String NAMESPACE = "eu.europa.ec.eudi.pda1.1";

    private final AuthSourceHelper authSourceHelper;
    private final IssuerSigningService issuerSigningService;

    public MDocIssuerService(AuthSourceHelper authSourceHelper, IssuerSigningService issuerSigningService) {
        this.authSourceHelper = authSourceHelper;
        this.issuerSigningService = issuerSigningService;
    }

    /**
     * Generate an mDoc credential in CBOR format using Authlete's IssuerSignedBuilder.
     * This method leverages the high-level builder API which handles:
     * - MSO (Mobile Security Object) creation
     * - Digest computation (SHA-256)
     * - IssuerAuth (COSE_Sign1) signature
     * - Namespace structuring
     * - ISO 18013-5 compliance
     *
     * @param walletKey      The wallet's public key (JWK format)
     * @param userIdentifier The user identifier to retrieve claims
     * @return CBOR-encoded IssuerSigned structure (mDoc)
     */
    public byte[] generateMDoc(JWK walletKey, String userIdentifier)
            throws JOSEException, COSEException, CertificateException {

        // 1. Get issuer's EC signing key and convert to COSE key
        ECKey issuerEcKey = issuerSigningService.getSigningKey();
        COSEEC2Key issuerCOSEKey = jwkToCOSEKey(issuerEcKey, true);

        // 2. Get issuer's certificate chain from SSL bundle
        List<X509Certificate> issuerCertChain = loadIssuerCertificateChain();

        // 3. Convert wallet's JWK to COSE_Key (device key for binding)
        COSEKey deviceCOSEKey = jwkToCOSEKey(walletKey, false);

        // 4. Prepare all claims as a namespace map
        // IssuerSignedBuilder expects: {namespace -> {claim1: value1, claim2: value2}}
        Map<String, Object> claims = prepareAllClaims(userIdentifier);
        Map<String, Object> namespacedClaims = Map.of(
                NAMESPACE, claims  // Wrap all claims under the docType namespace
        );

        // 5. Create ValidityInfo (issuance time, valid from, valid until)
        ValidityInfo validityInfo = createValidityInfo();

        // 6. Use IssuerSignedBuilder to create the complete mDoc structure
        // The builder handles all the complexity internally:
        // - Creates IssuerNameSpaces with claims
        // - Computes digests for each IssuerSignedItem
        // - Builds MSO with value digests
        // - Signs MSO with issuer's key (IssuerAuth as COSE_Sign1)
        IssuerSigned issuerSigned = new IssuerSignedBuilder()
                .setDocType(DOC_TYPE)
                .setClaims(namespacedClaims)  // Claims must be namespaced
                .setValidityInfo(validityInfo)
                .setDeviceKey(deviceCOSEKey)
                .setIssuerKey(issuerCOSEKey)
                .setIssuerCertChain(issuerCertChain)  // Add certificate chain
                .build();

        // 7. Encode to CBOR bytes for transmission
        return issuerSigned.encode();
    }

    /**
     * Prepare all claims by merging normal claims and disclosable claims.
     * For mDoc, all claims are structured as IssuerSignedItems in the namespace.
     */
    private Map<String, Object> prepareAllClaims(String userIdentifier) {
        Map<String, Object> claims = new HashMap<>();

        // Add credential holder claims (flattened for mDoc)
        Map<String, Object> credHolder = authSourceHelper.getCredentialHolder(userIdentifier);
        claims.put("credential_holder", credHolder);

        // Add competent institution claims
        Map<String, Object> institution = authSourceHelper.getCompetentInstitution(userIdentifier);
        claims.put("competent_institution", institution);

        // Add any normal claims
        claims.putAll(authSourceHelper.getNormalClaims(userIdentifier));

        return claims;
    }

    /**
     * Convert Nimbus JWK (JSON Web Key) to Authlete COSE_Key format
     * using the built-in COSEKey.fromJwk() utility method.
     *
     * @param jwk               The JWK to convert
     * @param includePrivateKey Whether to include the private key (d parameter)
     * @return COSEEC2Key instance
     */
    private COSEEC2Key jwkToCOSEKey(JWK jwk, boolean includePrivateKey) throws JOSEException, COSEException {
        if (!(jwk instanceof ECKey)) {
            throw new JOSEException("Only EC (Elliptic Curve) keys are supported for mDoc");
        }

        // Convert JWK to Map
        Map<String, Object> jwkMap = jwk.toJSONObject();

        // Remove private key if not requested
        if (!includePrivateKey && jwkMap.containsKey("d")) {
            jwkMap = new HashMap<>(jwkMap);
            jwkMap.remove("d");
        }

        // Use Authlete's built-in converter
        COSEKey coseKey = COSEKey.fromJwk(jwkMap);

        if (!(coseKey instanceof COSEEC2Key)) {
            throw new JOSEException("JWK conversion resulted in non-EC2 COSE key");
        }

        return (COSEEC2Key) coseKey;
    }

    /**
     * Load issuer's X.509 certificate chain from the SSL bundle.
     *
     * @return List of X509Certificate (certificate chain)
     */
    private List<X509Certificate> loadIssuerCertificateChain() throws CertificateException {
        // Get x5c chain from IssuerSigningService (SSL bundle based)
        List<com.nimbusds.jose.util.Base64> x5cChain = issuerSigningService.getX5cChain();

        if (x5cChain == null || x5cChain.isEmpty()) {
            throw new CertificateException("No certificate chain available from IssuerSigningService");
        }

        // Parse the first (leaf) certificate
        byte[] certBytes = x5cChain.getFirst().decode();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certBytes));

        // Return as single-element list (no intermediate CA certs in this demo)
        return List.of(certificate);
    }

    /**
     * Create ValidityInfo with issuance time and expiration.
     *
     * @return ValidityInfo with 1 year validity period
     */
    private ValidityInfo createValidityInfo() {
        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime expiry = now.plusDays(365); // 1 year validity

        return new ValidityInfo(
                now,    // signed (issuance time)
                now,    // validFrom
                expiry  // validUntil
        );
    }

}

package com.example.issuer.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.authlete.sd.SDObjectEncoder;
import com.example.issuer.config.AppMetadataConfig;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class AuthleteHelper {

    private final AppMetadataConfig appMetadataConfig;
    private final AuthSourceHelper authSourceHelper;
    private final IssuerSigningService issuerSigningService;

    public AuthleteHelper(AppMetadataConfig appMetadataConfig, AuthSourceHelper authSourceHelper,
                          IssuerSigningService issuerSigningService) {
        this.appMetadataConfig = appMetadataConfig;
        this.authSourceHelper = authSourceHelper;
        this.issuerSigningService = issuerSigningService;
    }

    /**
     * Creates a Verifiable Credential in SD-JWT format with two-level recursive selective disclosure.
     *
     * Structure (EU Reference Demo Style):
     * - Parent objects (credential_holder, competent_institution) are themselves disclosures
     * - Each nested field within parents is also a separate disclosure
     * - Total: 8 disclosures (2 parent + 6 nested)
     */
    public SDJWT createVC(JWK walletKey, String userIdentifier) throws JOSEException, ParseException {
        JWK signingKey = issuerSigningService.getSigningKey();
        List<Base64> x5cChain = issuerSigningService.getX5cChain();

        List<Disclosure> allDisclosures = new ArrayList<>();

        // === STEP 1: Encode nested objects independently ===
        // Per EU Reference Demo, _sd_alg should only be at top level, not in nested objects

        // Encode credential_holder nested fields
        SDObjectEncoder credHolderEncoder = new SDObjectEncoder();
        credHolderEncoder.setDecoyMagnification(0.0, 0.0);
        Map<String, Object> encodedCredentialHolder =
            new LinkedHashMap<>(credHolderEncoder.encode(authSourceHelper.getCredentialHolder(userIdentifier)));
        encodedCredentialHolder.remove("_sd_alg");  // Remove from nested object
        allDisclosures.addAll(credHolderEncoder.getDisclosures());  // family_name, given_name, birth_date

        // Encode competent_institution nested fields
        SDObjectEncoder institutionEncoder = new SDObjectEncoder();
        institutionEncoder.setDecoyMagnification(0.0, 0.0);
        Map<String, Object> encodedInstitution =
            new LinkedHashMap<>(institutionEncoder.encode(authSourceHelper.getCompetentInstitution(userIdentifier)));
        encodedInstitution.remove("_sd_alg");  // Remove from nested object
        allDisclosures.addAll(institutionEncoder.getDisclosures());  // country_code, institution_id, institution_name

        // === STEP 2: Build top-level with parent objects as disclosures ===

        SDObjectBuilder topLevelBuilder = new SDObjectBuilder();

        // Non-disclosable claims
        long now = System.currentTimeMillis() / 1000L;
        long oneYearInSeconds = 365L * 24 * 60 * 60;

        topLevelBuilder.putClaim("vct", appMetadataConfig.getClaims().getVct());
        topLevelBuilder.putClaim("iss", appMetadataConfig.getClaims().getIss());
        topLevelBuilder.putClaim("iat", now);
        topLevelBuilder.putClaim("exp", now + oneYearInSeconds);  // EU Reference includes exp
        topLevelBuilder.putClaim("cnf", buildCnfForBindingKey(walletKey));

        // Add normal claims (non-disclosable)
        Map<String, Object> normalClaims = authSourceHelper.getNormalClaims(userIdentifier);
        for (var entry : normalClaims.entrySet()) {
            topLevelBuilder.putClaim(entry.getKey(), entry.getValue());
        }

        // === STEP 3: Make parent objects selectively-disclosable ===

        Disclosure credHolderDisclosure = new Disclosure("credential_holder", encodedCredentialHolder);
        topLevelBuilder.putSDClaim(credHolderDisclosure);
        allDisclosures.add(credHolderDisclosure);

        Disclosure institutionDisclosure = new Disclosure("competent_institution", encodedInstitution);
        topLevelBuilder.putSDClaim(institutionDisclosure);
        allDisclosures.add(institutionDisclosure);

        // === STEP 4: Build and sign ===

        Map<String, Object> payload = new LinkedHashMap<>(topLevelBuilder.build(true));  // true = include _sd_alg

        // Add decoys to top-level _sd array (EU Reference Demo style - typically 10 decoys)
        addDecoysToSdArray(payload, 10);

        SignedJWT credentialJwt = createCredentialJwt(payload, signingKey, x5cChain);

        return new SDJWT(credentialJwt.serialize(), allDisclosures);
    }

    private SignedJWT createCredentialJwt(
            Map<String, Object> payload, JWK signingKey, List<Base64> x5cChain)
            throws ParseException, JOSEException {

        // Create the header part of a credential JWT with x5c
        JWSHeader header = createCredentialJwtHeader(signingKey, x5cChain);

        // Create a credential JWT (not signed yet)
        SignedJWT jwt = new SignedJWT(header, JWTClaimsSet.parse(payload));

        // Create a signer
        JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(signingKey);

        // Let the signer sign the credential JWT
        jwt.sign(signer);

        return jwt;
    }

    private JWSHeader createCredentialJwtHeader(JWK signingKey, List<Base64> x5cChain) {
        JWSAlgorithm alg = JWSAlgorithm.parse(signingKey.getAlgorithm().getName());

        // Note: Don't include 'kid' when x5c is present (EU Reference style)
        // The certificate chain identifies the key
        return new JWSHeader.Builder(alg)
                .type(new JOSEObjectType("dc+sd-jwt"))
                .x509CertChain(x5cChain)
                .build();
    }

    private Map<String, Object> buildCnfForBindingKey(JWK bindingKey) {
        return Map.of("jwk", bindingKey.toJSONObject());
    }

    /**
     * Adds decoy hashes to the _sd array in the payload.
     * Decoys are random SHA-256 hashes that make it harder to determine
     * exactly how many real selectively-disclosable claims exist.
     */
    @SuppressWarnings("unchecked")
    private void addDecoysToSdArray(Map<String, Object> payload, int numDecoys) {
        try {
            Object sdObj = payload.get("_sd");
            if (sdObj instanceof List) {
                List<String> sdList = new ArrayList<>((List<String>) sdObj);

                SecureRandom random = new SecureRandom();
                MessageDigest digest = MessageDigest.getInstance("SHA-256");

                for (int i = 0; i < numDecoys; i++) {
                    // Generate random bytes and hash them
                    byte[] randomBytes = new byte[32];
                    random.nextBytes(randomBytes);
                    byte[] hash = digest.digest(randomBytes);

                    // Encode as base64url (same format as real disclosure hashes)
                    String decoyHash = java.util.Base64.getUrlEncoder()
                            .withoutPadding()
                            .encodeToString(hash);
                    sdList.add(decoyHash);
                }

                // Sort the array (SD-JWT spec recommends sorting for privacy)
                java.util.Collections.sort(sdList);
                payload.put("_sd", sdList);
            }
        } catch (Exception e) {
            // If decoy generation fails, continue without decoys
        }
    }

}

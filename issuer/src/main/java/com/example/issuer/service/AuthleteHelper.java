package com.example.issuer.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.example.issuer.config.AppMetadataConfig;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Component
public class AuthleteHelper {

    private final AppMetadataConfig appMetadataConfig;
    private final AuthSourceHelper authSourceHelper;

    public AuthleteHelper(AppMetadataConfig appMetadataConfig, AuthSourceHelper authSourceHelper) {
        this.appMetadataConfig = appMetadataConfig;
        this.authSourceHelper = authSourceHelper;
    }

    public SDJWT createVC(JWK issuerKey, JWK walletKey, String userIdentifier) throws JOSEException, ParseException {
        Map<String, Object> claims = authSourceHelper.getNormalClaims(userIdentifier);
        List<Disclosure> disclosableClaims = authSourceHelper.getDisclosableClaims(userIdentifier);

        // Create a credential JWT, which is part of an SD-JWT.
        SignedJWT credentialJwt = createCredentialJwt(
                claims, disclosableClaims, issuerKey, walletKey);

        // Create a verifiable credential in the SD-JWT format.
        return new SDJWT(credentialJwt.serialize(), disclosableClaims);
    }

    private SignedJWT createCredentialJwt(
            Map<String, Object> claims, List<Disclosure> disclosableClaims,
            JWK signingKey, JWK bindingKey) throws ParseException, JOSEException {

        // Create the header part of a credential JWT.
        JWSHeader header = createCredentialJwtHeader(signingKey);

        // Create the payload part of a credential JWT.
        Map<String, Object> payload = createCredentialJwtPayload(claims, disclosableClaims, bindingKey);

        // Create a credential JWT. (not signed yet)
        SignedJWT jwt = new SignedJWT(header, JWTClaimsSet.parse(payload));

        // Create a signer.
        JWSSigner signer = new DefaultJWSSignerFactory().createJWSSigner(signingKey);

        // Let the signer sign the credential JWT.
        jwt.sign(signer);

        return jwt;
    }

    private JWSHeader createCredentialJwtHeader(JWK signingKey) {
        JWSAlgorithm alg = JWSAlgorithm.parse(signingKey.getAlgorithm().getName());
        String kid = signingKey.getKeyID();

        return new JWSHeader.Builder(alg).keyID(kid)
                .type(new JOSEObjectType("vc+sd-jwt")) // todo
                .build();
    }

    private Map<String, Object> createCredentialJwtPayload(
            Map<String, Object> claims, List<Disclosure> disclosableClaims, JWK bindingKey) {

        SDObjectBuilder builder = new SDObjectBuilder();

        // Add required VC claims
        builder.putClaim("vct", appMetadataConfig.getClaims().getVct());
        builder.putClaim("iss", appMetadataConfig.getClaims().getIss());
        builder.putClaim("iat", System.currentTimeMillis() / 1000L);
        builder.putClaim("cnf", buildCnfForBindingKey(bindingKey));

        // Add normal claims
        for (var claim : claims.entrySet()) {
            builder.putClaim(claim.getKey(), claim.getValue());
        }

        // Add disclosable claims
        for (var claim : disclosableClaims) {
            builder.putSDClaim(claim);
        }

        return builder.build();
    }

    private Map<String, Object> buildCnfForBindingKey(JWK bindingKey) {
        return Map.of("jwk", bindingKey.toJSONObject());
    }

}

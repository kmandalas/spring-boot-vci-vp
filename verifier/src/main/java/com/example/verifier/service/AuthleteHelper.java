package com.example.verifier.service;

import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.security.Key;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Map;

@Component
public class AuthleteHelper {

    public void verifyVP(SDJWT vp, JWK issuerKey) throws ParseException, JOSEException {
        // 1. Verify the credential JWT.
        verifyCredentialJwt(vp, issuerKey);

        // 2. Verify the binding JWT.
        verifyBindingJwt(vp);
    }

    private void verifyCredentialJwt(SDJWT vp, JWK issuerKey) throws ParseException, JOSEException {
        // Parse the credential JWT.
        SignedJWT credentialJwt = SignedJWT.parse(vp.getCredentialJwt());

        // Verify the signature of the credential JWT.
        boolean verified = verifySignature(credentialJwt, issuerKey);
        Assert.isTrue(verified, "Credential JWT signature verification failed.");

        // There are other aspects to be verified. For example, it should
        // be confirmed that the payload contains the "iss" claim.
        // However, this example code is not intended to be exhaustive.
    }

    private void verifyBindingJwt(SDJWT vp) throws ParseException, JOSEException {
        // Extract the binding key from the payload of the credential JWT.
        JWK bindingKey = extractBindingKey(vp);

        // Parse the binding JWT.
        SignedJWT bindingJwt = SignedJWT.parse(vp.getBindingJwt());

        // Verify the signature of the binding JWT.
        boolean verified = verifySignature(bindingJwt, bindingKey);
        Assert.isTrue(verified, "Binding JWT signature verification failed.");

        // Extract the value of the "sd_hash" from the binding JWT.
        String sdHash = bindingJwt.getJWTClaimsSet().getStringClaim("sd_hash");

        // The value of the "sd_hash" in the binding JWT must match
        // the actual SD hash value of the verifiable presentation.
        Assert.isTrue(vp.getSDHash().equals(sdHash), sdHash);

        // There are other aspects to be verified. For example, the "typ"
        // parameter in the JWS header should be confirmed to be "kb+jwt".
        // However, this example code is not intended to be exhaustive.
    }

    @SuppressWarnings("unchecked")
    private static JWK extractBindingKey(SDJWT vp) throws ParseException {
        // Parse the credential JWT.
        SignedJWT jwt = SignedJWT.parse(vp.getCredentialJwt());

        // The claims of the credential JWT.
        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        // cnf
        Object cnf = claims.getClaim("cnf");

        // jwk
        Object jwk = ((Map<String, Object>)cnf).get("jwk");

        // Convert to a JWK instance.
        return JWK.parse((Map<String, Object>)jwk);
    }

    private boolean verifySignature(SignedJWT jwt, JWK verificationKey) throws JOSEException {
        // Create a verifier.
        JWSVerifier verifier = createVerifier(jwt, verificationKey);

        // Verify the signature.
        return jwt.verify(verifier);
    }

    private JWSVerifier createVerifier(SignedJWT jwt, JWK verificationKey) throws JOSEException {
        // Convert the JWK to a PublicKey.
        Key key = convertToPublicKey(verificationKey);

        // Create a verifier.
        return new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader(), key);
    }

    private PublicKey convertToPublicKey(JWK jwk) throws JOSEException {
        // The "kty" (key type) of the JWK.
        KeyType keyType = jwk.getKeyType();

        // EC
        if (KeyType.EC.equals(keyType)) {
            return jwk.toECKey().toPublicKey();
        }
        // RSA
        else if (KeyType.RSA.equals(keyType)) {
            return jwk.toRSAKey().toPublicKey();
        }
        // OKP
        else if (KeyType.OKP.equals(keyType)) {
            return jwk.toOctetKeyPair().toPublicKey();
        }
        else {
            throw new JOSEException(String.format("The key type '%s' is not supported.", keyType));
        }
    }

}

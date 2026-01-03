package com.example.issuer.service;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;

/**
 * Service for SD-JWT signing with X.509 certificate support.
 * Loads certificate and private key via Spring Boot SSL Bundles.
 */
@Service
public class IssuerSigningService {

    private final List<Base64> x5cChain;
    private final ECKey ecJwk;

    public IssuerSigningService(SslBundles sslBundles) throws Exception {
        SslBundle bundle = sslBundles.getBundle("issuer-signing");
        KeyStore keyStore = bundle.getStores().getKeyStore();

        // Get the first (and only) alias from the keystore
        String alias = keyStore.aliases().nextElement();

        // Extract private key and certificate
        ECPrivateKey privateKey = (ECPrivateKey) keyStore.getKey(alias, null);
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        ECPublicKey publicKey = (ECPublicKey) certificate.getPublicKey();

        // Build x5c chain (just the issuer cert for self-signed)
        this.x5cChain = List.of(Base64.encode(certificate.getEncoded()));

        // Build ECKey JWK for JWKS endpoint and signing
        this.ecJwk = new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID("issuer-key-1")
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256)
                .build();
    }

    /**
     * Returns the EC JWK for signing (includes private key).
     */
    public ECKey getSigningKey() {
        return ecJwk;
    }

    /**
     * Returns the public EC JWK for the JWKS endpoint.
     */
    public ECKey getPublicJwk() {
        return ecJwk.toPublicJWK();
    }

    /**
     * Returns the x5c certificate chain for JWT headers.
     */
    public List<Base64> getX5cChain() {
        return x5cChain;
    }

    /**
     * Returns the JWKS response for /.well-known/jwks.json
     */
    public Map<String, Object> getJwksResponse() {
        return Map.of("keys", List.of(getPublicJwk().toJSONObject()));
    }

}

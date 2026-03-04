package com.example.issuer;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Test;

import java.io.FileReader;
import java.io.FileInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

/**
 * Generates JWKS needed for the OpenID Foundation conformance suite.
 * Run with: mvn test -Dtest=ConformanceJwksGenerator -pl issuer
 *
 * Outputs:
 *   1. Client 1 JWKS  → paste into "Client > jwks" (first client)
 *   2. Client 2 JWKS  → paste into "Second client > jwks"
 *   3. Attester JWKS  → paste into "Client Attestation > Client Attester Keys JWKS"
 */
class ConformanceJwksGenerator {

    private static final String WP_KEY_PEM  = "../wallet-provider/src/main/resources/wp_key.pem";
    private static final String WP_CERT_PEM = "../wallet-provider/src/main/resources/wp_cert.pem";

    @Test
    void generateConformanceJwks() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // --- 1 & 2: Fresh client key pairs ---
        ECKey client1 = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).keyID("client1-key").generate();
        ECKey client2 = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).keyID("client2-key").generate();

        System.out.println("============================================================");
        System.out.println("  Client 1 JWKS  →  paste into: Client > jwks");
        System.out.println("============================================================");
        System.out.println("{\"keys\":[" + client1.toJSONString() + "]}");

        System.out.println();
        System.out.println("============================================================");
        System.out.println("  Client 2 JWKS  →  paste into: Second client > jwks");
        System.out.println("============================================================");
        System.out.println("{\"keys\":[" + client2.toJSONString() + "]}");

        // --- 3: Attester JWKS from wallet-provider PEM files ---
        // Parse private key
        PEMParser pemParser = new PEMParser(new FileReader(WP_KEY_PEM));
        Object obj = pemParser.readObject();
        pemParser.close();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        ECPrivateKey privateKey = (ECPrivateKey) converter.getPrivateKey(((PEMKeyPair) obj).getPrivateKeyInfo());

        // Parse certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(WP_CERT_PEM));
        ECPublicKey publicKey = (ECPublicKey) cert.getPublicKey();

        // Build JWK with private key + x5c
        ECKey attesterJwk = new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("attester-key")
                .x509CertChain(List.of(Base64.encode(cert.getEncoded())))
                .build();

        System.out.println();
        System.out.println("============================================================");
        System.out.println("  Attester JWKS  →  paste into: Client Attester Keys JWKS");
        System.out.println("============================================================");
        System.out.println("{\"keys\":[" + attesterJwk.toJSONString() + "]}");
        System.out.println();
    }
}

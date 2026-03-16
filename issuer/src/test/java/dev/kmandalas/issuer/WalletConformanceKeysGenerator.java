package dev.kmandalas.issuer;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

/**
 * Generates keys needed for the OID4VCI "Testing a Wallet" conformance suite
 * on www.certification.openid.net.
 *
 * In the wallet conformance tests, the suite EMULATES the Issuer + Authorization Server.
 * It needs signing keys (with x5c certificate chain) to issue credentials to our wallet.
 * These keys must be pasted into the suite's test plan configuration form.
 *
 * Run with: mvn test -Dtest=WalletConformanceKeysGenerator -pl issuer
 *
 * Outputs:
 *   1. Credential Issuer > Signing JWK  → the key the suite uses to sign issued credentials
 *                                          (full JWK with private key "d" and x5c chain)
 *   2. Server > jwks                    → the suite's server JWKS (with private keys)
 *                                          used for token signing / general server operations
 */
class WalletConformanceKeysGenerator {

    @Test
    void generateWalletConformanceKeys() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // --- 1: Credential Issuer Signing JWK (with self-signed x5c) ---
        // The suite uses this key to sign the credential it issues to the wallet.
        // HAIP requires x5c in the credential JWT header, so the JWK must include a certificate chain.
        ECKey rawKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("suite-issuer-key")
                .generate();

        // Generate self-signed certificate for the key
        KeyPair keyPair = rawKey.toKeyPair();
        X509Certificate cert = generateSelfSignedCert(
                (ECPublicKey) keyPair.getPublic(),
                (ECPrivateKey) keyPair.getPrivate(),
                "CN=conformance-suite-issuer"
        );

        // Rebuild JWK with x5c
        ECKey issuerSigningKey = new ECKey.Builder(rawKey)
                .x509CertChain(List.of(Base64.encode(cert.getEncoded())))
                .build();

        System.out.println("============================================================");
        System.out.println("  Credential Issuer > Signing JWK");
        System.out.println("  Paste the FULL JWK (with 'd' and 'x5c') into the field.");
        System.out.println("============================================================");
        System.out.println(issuerSigningKey.toJSONString());

        // --- 2: Server JWKS ---
        // The suite's server keys (e.g. for signing tokens).
        ECKey serverKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(JWSAlgorithm.ES256)
                .keyID("suite-server-key")
                .generate();

        System.out.println();
        System.out.println("============================================================");
        System.out.println("  Server > jwks");
        System.out.println("  Paste the JWKS (with private key) into the field.");
        System.out.println("============================================================");
        System.out.println(new JWKSet(serverKey).toString(false));
        System.out.println();
    }

    /**
     * Generate a self-signed X.509 certificate valid for 1 year.
     */
    private static X509Certificate generateSelfSignedCert(
            ECPublicKey publicKey, ECPrivateKey privateKey, String subjectDN) throws Exception {

        Instant now = Instant.now();
        X500Name subject = new X500Name(subjectDN);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                publicKey
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(privateKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

}

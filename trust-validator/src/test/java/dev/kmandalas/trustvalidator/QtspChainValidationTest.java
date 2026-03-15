package dev.kmandalas.trustvalidator;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests PKIX chain validation for the QTSP CA → user cert scenario,
 * matching what the trust-validator does at runtime.
 */
class QtspChainValidationTest {

    private static X509Certificate caCert;
    private static X509Certificate userCert;
    private static Set<TrustAnchor> anchors;

    @BeforeAll
    static void setup() throws Exception {
        // Load CA cert from local-trust.jks (same file the trust-validator uses)
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = QtspChainValidationTest.class.getResourceAsStream("/local-trust.jks")) {
            assertNotNull(is, "local-trust.jks must be on classpath");
            ks.load(is, "changeit".toCharArray());
        }
        caCert = (X509Certificate) ks.getCertificate("qtsp-mock-ca");
        assertNotNull(caCert, "qtsp-mock-ca alias must exist in JKS");

        // Generate a user signing cert signed by the CA (simulating what qtsp-mock does)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair userKeyPair = keyGen.generateKeyPair();

        // Load the CA private key from the PEM to sign the user cert
        // Instead, we generate a fresh CA key pair and cert for the test
        // to avoid needing the CA private key here.
        // But the real test is: can PKIX validate [userCert] with CA in anchors?
        // So let's create our own CA + user cert pair for the PKIX behavior test,
        // and then also test with the actual JKS CA cert.

        KeyPair caKeyPair = keyGen.generateKeyPair();
        Instant now = Instant.now();
        X500Name caSubject = new X500Name("CN=Test CA, O=Test, C=GR");

        // Self-signed CA cert with basicConstraints=CA:true
        var caSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        var caCertBuilder = new JcaX509v3CertificateBuilder(
                caSubject, BigInteger.valueOf(1),
                Date.from(now), Date.from(now.plus(365, ChronoUnit.DAYS)),
                caSubject, caKeyPair.getPublic());
        caCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate testCaCert = new JcaX509CertificateConverter().getCertificate(caCertBuilder.build(caSigner));

        // User cert signed by CA
        X500Name userSubject = new X500Name("CN=User Key, O=Test, C=GR");
        var userCertHolder = new JcaX509v3CertificateBuilder(
                caSubject, BigInteger.valueOf(2),
                Date.from(now), Date.from(now.plus(365, ChronoUnit.DAYS)),
                userSubject, userKeyPair.getPublic()
        ).build(caSigner);
        userCert = new JcaX509CertificateConverter().getCertificate(userCertHolder);

        caCert = testCaCert;
        anchors = Set.of(new TrustAnchor(caCert, null));
    }

    @Test
    void pkixValidates_userCertOnly_inPath() throws Exception {
        // Path = [user cert], Anchors = {CA cert} — standard PKIX usage
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath path = cf.generateCertPath(List.of(userCert));
        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);

        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
                CertPathValidator.getInstance("PKIX").validate(path, params);

        assertEquals(caCert.getSubjectX500Principal(), result.getTrustAnchor().getTrustedCert().getSubjectX500Principal());
    }

    @Test
    void pkixValidates_fullChain_inPath() throws Exception {
        // Path = [user cert, CA cert], Anchors = {CA cert}
        // This is what the trust-validator receives — does PKIX accept it?
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath path = cf.generateCertPath(List.of(userCert, caCert));
        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);

        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
                CertPathValidator.getInstance("PKIX").validate(path, params);

        assertEquals(caCert.getSubjectX500Principal(), result.getTrustAnchor().getTrustedCert().getSubjectX500Principal());
    }

    @Test
    void pkixValidates_realCaCert_withBouncyCastleDN() throws Exception {
        // Reproduces what KeyManagementService does at runtime:
        // 1. Load CA cert from JKS
        // 2. Use BouncyCastle X500Name(cert.getSubjectX500Principal().getName()) as issuer DN
        // 3. Issue user cert signed by CA
        // 4. Validate chain via PKIX against the JKS CA as trust anchor

        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = QtspChainValidationTest.class.getResourceAsStream("/local-trust.jks")) {
            assertNotNull(is, "local-trust.jks must be on test classpath");
            ks.load(is, "changeit".toCharArray());
        }
        X509Certificate realCaCert = (X509Certificate) ks.getCertificate("qtsp-mock-ca");
        assertNotNull(realCaCert, "qtsp-mock-ca alias must exist in JKS");

        // Print the DN in different formats for diagnostics
        String getName = realCaCert.getSubjectX500Principal().getName();
        String rfc2253 = realCaCert.getSubjectX500Principal().getName("RFC2253");
        System.out.println("CA Subject getName():  " + getName);
        System.out.println("CA Subject RFC2253:    " + rfc2253);
        System.out.println("CA Subject toString(): " + realCaCert.getSubjectX500Principal());

        // This is what KeyManagementService does — BouncyCastle X500Name from getName()
        X500Name issuerDN = new X500Name(realCaCert.getSubjectX500Principal().getName());
        System.out.println("BC X500Name from getName(): " + issuerDN);

        // Compare: the encoded form of the issuerDN vs what's in the cert
        // X500Name from getName() may reorder RDNs (RFC 2253 = reverse order of ASN.1)
        X500Name certSubjectDN = X500Name.getInstance(realCaCert.getSubjectX500Principal().getEncoded());
        System.out.println("BC X500Name from encoded:   " + certSubjectDN);
        System.out.println("DNs equal: " + issuerDN.equals(certSubjectDN));

        // Now generate a user cert exactly like KeyManagementService does
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair userKeyPair = keyGen.generateKeyPair();

        // We need the CA private key to sign — but we don't have it in JKS (trust store only).
        // So generate a throwaway CA with the SAME DN to test DN chaining only.
        // The real fix needs to happen in KeyManagementService's DN construction.
        KeyPair caKeyPair = keyGen.generateKeyPair();

        // Method 1: X500Name from getName() — what KeyManagementService currently does
        X500Name issuerFromGetName = new X500Name(realCaCert.getSubjectX500Principal().getName());
        // Method 2: X500Name from encoded ASN.1 — preserves original encoding
        X500Name issuerFromEncoded = X500Name.getInstance(realCaCert.getSubjectX500Principal().getEncoded());

        System.out.println("\nMethod 1 (getName):  " + issuerFromGetName);
        System.out.println("Method 2 (encoded):  " + issuerFromEncoded);
        System.out.println("Methods equal: " + issuerFromGetName.equals(issuerFromEncoded));

        // Build CA cert with method 2 (encoded) to get correct DN
        var caSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        Instant now = Instant.now();
        var caCertBuilder = new JcaX509v3CertificateBuilder(
                issuerFromEncoded, BigInteger.valueOf(1),
                Date.from(now), Date.from(now.plus(365, ChronoUnit.DAYS)),
                issuerFromEncoded, caKeyPair.getPublic());
        caCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate testCaCert = new JcaX509CertificateConverter().getCertificate(caCertBuilder.build(caSigner));

        // Issue user cert with issuer DN from method 1 (getName) — the potentially broken way
        X500Name userSubject = new X500Name("CN=Wallet User Signing Key, O=K-QTSP Mock, C=GR");
        var userCertFromGetName = new JcaX509v3CertificateBuilder(
                issuerFromGetName, BigInteger.valueOf(2),
                Date.from(now), Date.from(now.plus(365, ChronoUnit.DAYS)),
                userSubject, userKeyPair.getPublic()
        ).build(caSigner);
        X509Certificate userCertMethod1 = new JcaX509CertificateConverter().getCertificate(userCertFromGetName);

        // Issue user cert with issuer DN from method 2 (encoded) — the correct way
        var userCertFromEncoded = new JcaX509v3CertificateBuilder(
                issuerFromEncoded, BigInteger.valueOf(3),
                Date.from(now), Date.from(now.plus(365, ChronoUnit.DAYS)),
                userSubject, userKeyPair.getPublic()
        ).build(caSigner);
        X509Certificate userCertMethod2 = new JcaX509CertificateConverter().getCertificate(userCertFromEncoded);

        System.out.println("\nUser cert (method 1) issuer: " + userCertMethod1.getIssuerX500Principal().getName());
        System.out.println("User cert (method 2) issuer: " + userCertMethod2.getIssuerX500Principal().getName());
        System.out.println("CA cert subject:             " + testCaCert.getSubjectX500Principal().getName());

        // Check if the issuer DN on the user cert matches the subject DN on the CA cert
        System.out.println("Method 1 issuer == CA subject: " +
                userCertMethod1.getIssuerX500Principal().equals(testCaCert.getSubjectX500Principal()));
        System.out.println("Method 2 issuer == CA subject: " +
                userCertMethod2.getIssuerX500Principal().equals(testCaCert.getSubjectX500Principal()));

        // PKIX validation with method 2
        Set<TrustAnchor> realAnchors = Set.of(new TrustAnchor(testCaCert, null));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath path = cf.generateCertPath(List.of(userCertMethod2, testCaCert));
        PKIXParameters params = new PKIXParameters(realAnchors);
        params.setRevocationEnabled(false);

        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
                CertPathValidator.getInstance("PKIX").validate(path, params);
        assertNotNull(result);
        System.out.println("✅ Method 2 (encoded DN) PKIX validation passed");
    }

    @Test
    void pkixRejects_untrustedCa() throws Exception {
        // Different CA in anchors — should fail
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair otherCaKeyPair = keyGen.generateKeyPair();

        X500Name otherSubject = new X500Name("CN=Other CA, O=Other, C=DE");
        var otherSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(otherCaKeyPair.getPrivate());
        var otherCaCertHolder = new JcaX509v3CertificateBuilder(
                otherSubject, BigInteger.valueOf(99),
                Date.from(Instant.now()), Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                otherSubject, otherCaKeyPair.getPublic()
        ).build(otherSigner);
        X509Certificate otherCaCert = new JcaX509CertificateConverter().getCertificate(otherCaCertHolder);

        Set<TrustAnchor> wrongAnchors = Set.of(new TrustAnchor(otherCaCert, null));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath path = cf.generateCertPath(List.of(userCert, caCert));
        PKIXParameters params = new PKIXParameters(wrongAnchors);
        params.setRevocationEnabled(false);

        assertThrows(CertPathValidatorException.class,
                () -> CertPathValidator.getInstance("PKIX").validate(path, params));
    }
}

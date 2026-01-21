package com.example.authserver.wia;

import com.nimbusds.jose.jwk.JWK;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Authentication token for OAuth Attestation-Based Client Authentication.
 * Holds the WIA JWT, PoP JWT, DPoP JWT, and extracted wallet public key.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/">
 *      draft-ietf-oauth-attestation-based-client-auth</a>
 */
public class WalletAttestationAuthenticationToken extends OAuth2ClientAuthenticationToken {

    /**
     * Client authentication method identifier for attestation-based client authentication.
     */
    public static final ClientAuthenticationMethod ATTEST_JWT_CLIENT_AUTH =
            new ClientAuthenticationMethod("attest_jwt_client_auth");

    private final String wiaJwt;
    private final String popJwt;
    private final String dpopJwt;
    private final JWK walletPublicKey;

    /**
     * Creates an unauthenticated token (before validation).
     *
     * @param clientId the client identifier extracted from WIA sub claim
     * @param wiaJwt   the Wallet Instance Attestation JWT
     * @param popJwt   the Proof of Possession JWT
     * @param dpopJwt  the DPoP JWT (may be null)
     */
    public WalletAttestationAuthenticationToken(String clientId, String wiaJwt, String popJwt, String dpopJwt) {
        super(clientId, ATTEST_JWT_CLIENT_AUTH, null, null);
        this.wiaJwt = wiaJwt;
        this.popJwt = popJwt;
        this.dpopJwt = dpopJwt;
        this.walletPublicKey = null;
    }

    /**
     * Creates an authenticated token (after validation).
     *
     * @param registeredClient the registered client
     * @param wiaJwt           the validated Wallet Instance Attestation JWT
     * @param popJwt           the validated Proof of Possession JWT
     * @param dpopJwt          the DPoP JWT (may be null)
     * @param walletPublicKey  the wallet's public key extracted from WIA cnf.jwk
     */
    public WalletAttestationAuthenticationToken(RegisteredClient registeredClient,
                                                 String wiaJwt,
                                                 String popJwt,
                                                 String dpopJwt,
                                                 JWK walletPublicKey) {
        super(registeredClient, ATTEST_JWT_CLIENT_AUTH, null);
        this.wiaJwt = wiaJwt;
        this.popJwt = popJwt;
        this.dpopJwt = dpopJwt;
        this.walletPublicKey = walletPublicKey;
    }

    public String getWiaJwt() {
        return wiaJwt;
    }

    public String getPopJwt() {
        return popJwt;
    }

    public String getDpopJwt() {
        return dpopJwt;
    }

    public JWK getWalletPublicKey() {
        return walletPublicKey;
    }

}

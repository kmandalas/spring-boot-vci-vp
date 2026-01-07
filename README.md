# Spring Boot SD-JWT & VCI/VP Demo
Explore how SD-JWTs, OIDC4VCI, and OIDC4VP enable user-consented, selective disclosure of Verifiable Credentials using open standards in a demo setup. This implementation follows the [HAIP (High Assurance Interoperability Profile)](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) specification.

## VCI

### Wallet-Initiated Issuance after Installation

The End-User installs a new Wallet and opens it. The Wallet offers the End-User a selection of Credentials that the End-User may obtain from a Credential Issuer, e.g. a national identity Credential, a mobile driving license, or a public transport ticket. The corresponding Credential Issuers (and their URLs) are pre-configured by the Wallet or follow some discovery processes that are out of scope for this specification. By clicking on one of these options corresponding to the Credentials available for issuance, the issuance process starts using a flow supported by the Credential Issuer (Pre-Authorized Code flow or Authorization Code flow).

Wallet Providers may also provide a marketplace where Issuers can register to be found for Wallet-initiated flows.

References:
- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.3
- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-wallet-initiated-issuance-a

```
sequenceDiagram
    participant User
    participant WalletApp
    participant IssuerAuthServer as Authorization Server
    participant Issuer
    participant AuthenticSource

    User->>WalletApp: Opens wallet app
    User->>WalletApp: Unlocks app with biometrics
    User->>WalletApp: Selects "Request VC" deep link
    WalletApp->>IssuerAuthServer: Redirect to login (Auth Code Flow)

    Note over User,IssuerAuthServer: Browser is opened for authentication and consent

    User->>IssuerAuthServer: Provides credentials and consent
    IssuerAuthServer-->>WalletApp: Redirect with auth code (via deep link)
    WalletApp->>WalletApp: Generate DPoP proof
    WalletApp->>IssuerAuthServer: Exchange code for access token (with DPoP)
    IssuerAuthServer-->>WalletApp: Respond with DPoP-bound access token
    WalletApp->>WalletApp: Prepare credential request with JWT proof
    WalletApp->>Issuer: Call credential endpoint with JWT proof + DPoP
    Issuer->>Issuer: Validate DPoP proof and JWT proof
    Issuer->>AuthenticSource: Retrieve user credentials
    AuthenticSource-->>Issuer: Return credentials
    Issuer->>Issuer: Prepare SD-JWT with x5c header
    Issuer-->>WalletApp: Return SD-JWT (dc+sd-jwt format)
    WalletApp->>WalletApp: Verify SD-JWT signature using x5c certificate
    WalletApp->>WalletApp: Decode & Display verifiable credentials
    WalletApp->>WalletApp: Save credentials in Encrypted Shared Preferences
```

![vci-auth-code-flow.png](vci-auth-code-flow.png)

#### SD-JWT

The credential is issued in `dc+sd-jwt` format with an x5c certificate chain in the header for signature verification.

Sample (demo):
```
TODO: Add fresh SD-JWT sample with x5c header
```

💡 Paste it on https://www.sdjwt.co for inspection.

![sdjwt.png](sdjwt.png)

---

## Demo wallet app (Android)

Available [here](https://github.com/kmandalas/android-vci-vp) along with instructions.
Additionally, you can watch a screen recording that walks through the entire flow on [YouTube](https://youtube.com/shorts/cxIgyTR8s6w).

---

## VP

### Same Device Flow (our demo)

The verifier uses JWT-Secured Authorization Request (JAR) with x5c certificate chain for request authentication, and the wallet encrypts the VP response using ECDH-ES + A256GCM.

```
sequenceDiagram
    participant UA as User Agent
    participant W as Wallet
    participant V as Verifier
    participant IS as Issuer
    UA ->> V: Trigger presentation
    V ->> V: Generate ephemeral encryption key pair
    V ->> V: Create authorization request with DCQL query
    V ->> V: Sign request as JAR (JWT with x5c header)
    V -->> UA: Render request as QR/deep link (haip-vp://)
    UA ->> W: Trigger wallet and pass request
    W ->> V: GET request_uri (Accept: application/oauth-authz-req+jwt)
    V -->> W: Signed JAR
    W ->> W: Verify JAR signature using x5c certificate
    W ->> W: Validate x509_hash matches client_id
    W ->> W: Parse DCQL query from verified JWT
    W ->> W: Fetch locally stored VC
    W ->> W: Prompt user for selective disclosure
    W ->> W: Create VP with Key Binding JWT
    W ->> W: Encrypt response (ECDH-ES + A256GCM)
    W ->> V: POST encrypted vp_token (direct_post.jwt)
    V ->> V: Decrypt response with ephemeral private key
    V ->> IS: Fetch issuer's public key (or use x5c from credential)
    V ->> V: Verify SD-JWT credential signature
    V ->> V: Verify Key Binding JWT
    V -->> W: Return verification result
    W ->> W: Display verification outcome
```

![vp-same-device-flow.png](vp-same-device-flow.png)

### DCQL Query

The verifier uses DCQL (Digital Credentials Query Language) to request specific claims from credentials.

Sample (demo):
```json
{
  "client_id": "x509_hash:a54_NCUlnbgC-1PfaZIppUTinKy4ITcmSo6KtXxyFCE",
  "response_type": "vp_token",
  "response_mode": "direct_post.jwt",
  "response_uri": "https://verifier.example.com/verify-vp/{requestId}",
  "nonce": "e2c1d8f1-ffc1-4412-871d-94a4bc14a6b5",
  "dcql_query": {
    "credentials": [
      {
        "id": "pda1_credential",
        "format": "dc+sd-jwt",
        "meta": {
          "vct_values": ["urn:eu.europa.ec.eudi:pda1:1"]
        },
        "claims": [
          { "path": ["credential_holder"] },
          { "path": ["nationality"] },
          { "path": ["competent_institution"] }
        ]
      }
    ]
  },
  "client_metadata": {
    "client_name": "Demo Verifier Inc.",
    "logo_uri": "https://example.com/logo.png",
    "purpose": "Verify your Portable Document A1 credentials",
    "jwks": {
      "keys": [{ "kty": "EC", "crv": "P-256", "...": "ephemeral encryption key" }]
    },
    "authorization_encrypted_response_alg": "ECDH-ES",
    "authorization_encrypted_response_enc": "A256GCM"
  }
}
```

### vp_token Response

The wallet sends an encrypted JWE containing the vp_token in DCQL format:

```json
{
  "vp_token": {
    "pda1_credential": ["<SD-JWT with disclosures and KB-JWT>"]
  },
  "state": "optional-state-value"
}
```

Sample vp_token (demo):
```
TODO: Add fresh vp_token sample
```

💡 Paste it on https://www.sdjwt.co for inspection.

![vptoken.png](vptoken.png)

### QR code and Deep Link

The verifier generates deep links using the `haip-vp://` scheme (HAIP compliant) or `openid4vp://`:

```
haip-vp://?client_id=x509_hash%3Aa54_NCUlnbgC-1PfaZIppUTinKy4ITcmSo6KtXxyFCE&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest-object%2F{requestId}
```

---

## HAIP Features

This implementation includes the following HAIP-compliant features:

| Feature | Description |
|---------|-------------|
| **DPoP** | Demonstrating Proof of Possession for access tokens (RFC 9449) |
| **JAR with x5c** | JWT-Secured Authorization Requests signed with X.509 certificate |
| **x509_hash client_id** | Client identification via SHA-256 hash of DER-encoded certificate |
| **DCQL** | Digital Credentials Query Language for credential requests |
| **dc+sd-jwt** | HAIP-compliant credential format with x5c header |
| **VP Encryption** | Response encryption using ECDH-ES + A256GCM |
| **haip-vp:// scheme** | HAIP-compliant URI scheme for wallet invocation |

---

<details>
<summary>⚠️ Disclaimer</summary>

This repo contains an **experimental project** created for learning and demonstration purposes. The implementation is **not intended for production** use.

</details>

## VCI

### Wallet-Initiated Issuance after Installation 

The End-User installs a new Wallet and opens it. The Wallet offers the End-User a selection of Credentials that the End-User may obtain from a Credential Issuer, e.g. a national identity Credential, a mobile driving license, or a public transport ticket. The corresponding Credential Issuers (and their URLs) are pre-configured by the Wallet or follow some discovery processes that are out of scope for this specification. By clicking on one of these options corresponding to the Credentials available for issuance, the issuance process starts using a flow supported by the Credential Issuer (Pre-Authorized Code flow or Authorization Code flow).

Wallet Providers may also provide a marketplace where Issuers can register to be found for Wallet-initiated flows.

References:
- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-wallet-initiated-issuance-a
- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow

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
    WalletApp->>IssuerAuthServer: Exchange code for access token
    IssuerAuthServer-->>WalletApp: Respond with access token
    WalletApp->>WalletApp: Prepare credential request with JWT proof
    WalletApp->>Issuer: Call credential endpoint with JWT proof
    Issuer->>Issuer: Validate credential request and JWT proof
    Issuer->>AuthenticSource: Retrieve user credentials
    AuthenticSource-->>Issuer: Return credentials
    Issuer->>Issuer: Prepare SD-JWT
    Issuer-->>WalletApp: Return SD-JWT
    WalletApp->>WalletApp: Verify SD-JWT signature from Issuer
    WalletApp->>WalletApp: Decode & Display verifiable credentials
    WalletApp->>WalletApp: Save credentials in Encrypted Shared Preferences
```

![vci-auth-code-flow.png](vci-auth-code-flow.png)

#### SD-JWT

Sample (demo):
```
eyJraWQiOiJpc3N1ZXIta2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTkyLjE2OC4xLjY1L2NyZWRlbnRpYWwiLCJfc2QiOlsiVTdHSWJoLTl0NHlockhxZHN0OHp5bzdac1lyNmtRM2pnc2NCY1R1c21YVSIsIlhGT2V6WFpVZXBpOEZpQ3R0dFNoZVIzcEFYRE4tQXdnTC1MV0p2eldUX00iLCJicDk3WnlhOEtQR0tfYmtvUmRabHhSVDN4aklTcXJoeGVONVdZUlNleWhNIl0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImtpZCI6IndhbGxldC1rZXkiLCJ4IjoiUE5CYS1hS1AyTnAteU1PZkpOZ0JUY1Bvc3Z1MUUyM0o4SE5DR1VPLUhYdyIsInkiOiJLNDlqbDFNU1A0OUo2bHhLcExpRGt4YU1ZLUVSYnZOX1NlclhqZW85SlowIiwiYWxnIjoiRVMyNTYifX0sImNvbXBhbnkiOiJVc2VyQ29ycCIsImlhdCI6MTc0NjIyMjcyNywidmN0IjoidXJuOmV1LmV1cm9wYS5lYy5ldWRpOnBkYTE6MSJ9.NoLijxtEQVO9mZRK4b6vSb5jdcggQ5X8so8K9XKy8uOtDnSMQssGg0Y-YLKO-EcLH6IA1GacbSlJtl39IeESMg~WyJRd2xtMU4tQXBLOUlEQUxSZ25kM0dnIiwiY3JlZGVudGlhbF9ob2xkZXIiLCJOaWtvcyBUZXN0b3BvdWxvcyJd~WyJ6a3BiTDBVcDNPYzRxeFkza1EtaTdRIiwibmF0aW9uYWxpdHkiLCJHcmVlayDwn4es8J-HtyJd~WyJtdjVGT09SbDF3ZXZWQnRQR2t4NkdBIiwiY29tcGV0ZW50X2luc3RpdHV0aW9uIiwiRU9QWVkiXQ~
```
💡 Paste it on https://www.sdjwt.co for inspection.

---

## Demo wallet app (Android)

Available [here](https://github.com/kmandalas/android-vci-vp) along with instructions.
Additionally, you can watch a screen recording that walks through the entire flow on [YouTube](https://youtube.com/shorts/cxIgyTR8s6w).

---

## VP

### Same Device Flow (our demo) 🧪

```
sequenceDiagram
    participant UA as User Agent
    participant W as Wallet
    participant V as Verifier
    participant IS as Issuer
    UA ->> V: Trigger presentation
    V ->> V: Initiate transaction
    V -->> V: Authorization request as request_uri
    V -->> UA: Render request as deep link
    UA ->> W: Trigger wallet and pass request
    W ->> V: Get authorization request via request_uri
    V -->> W: authorization_request
    W ->> W: Parse authorization request
    alt opt
        W ->> V: Get presentation definition
        V -->> W: presentation_definition
    end
    W ->> W: Fetch locally stored VC
    W ->> W: Prompt user for selective discosure 
    W ->> W: Prepare response
    W ->> V: Post vp_token response
    V ->> IS: Fetch issuer's Public key
    V ->> V: Verify vp_token's credential JWT
    V ->> V: Verity vp_token's binding JWT
    V ->> V: Perform other validations and prepare response
    V -->> W: Return response_code
    W ->> W: Display verification outcome
```

![vp-same-device-flow.png](vp-same-device-flow.png)


### Input Descriptor samples

#### Presentation definition

Sample (demo):
```json
{
  "client_id": "verifier-backend.eudiw.cgn",
  "response_type": "vp_token",
  "response_mode": "direct_post",
  "response_uri": "<REPLACE_WITH_APP_CONFIG_RESPONSE_URI>",
  "nonce": "abc123",
  "presentation_definition": {
    "id": "presentation-definition-1",
    "name": "Portable Document A1 (PDA1)",
    "purpose": "Demo data sharing requirements",
    "input_descriptors": [
      {
        "id": "input-descriptor-1",
        "format": {
          "vc+sd-jwt": {
            "alg": ["ES256"]
          }
        },
        "constraints": {
          "fields": [
            {
              "path": ["$.vct"],
              "optional": "false",
              "filter": {
                "type": "string",
                "const": "urn:eu.europa.ec.eudi:pda1:1"
              }
            },
            {
              "path": ["$.credential_holder"],
              "optional": "false"
            },
            {
              "path": ["$.nationality"],
              "optional": "false"
            },
            {
              "path": ["$.competent_institution"],
              "optional": "false"
            }
          ]
        }
      }
    ]
  },
  "client_metadata": {
    "client_name": "Demo Verifier Inc.",
    "logo_uri": "https://img.freepik.com/premium-vector/creative-logo-design-real-estate-company-vector-illustration_1253202-20005.jpg?semt=ais_hybrid&w=120"
  }
}
```

#### vp_token

Sample (demo):
```
eyJraWQiOiJpc3N1ZXIta2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTkyLjE2OC4xLjY1L2NyZWRlbnRpYWwiLCJfc2QiOlsiVTdHSWJoLTl0NHlockhxZHN0OHp5bzdac1lyNmtRM2pnc2NCY1R1c21YVSIsIlhGT2V6WFpVZXBpOEZpQ3R0dFNoZVIzcEFYRE4tQXdnTC1MV0p2eldUX00iLCJicDk3WnlhOEtQR0tfYmtvUmRabHhSVDN4aklTcXJoeGVONVdZUlNleWhNIl0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsImtpZCI6IndhbGxldC1rZXkiLCJ4IjoiUE5CYS1hS1AyTnAteU1PZkpOZ0JUY1Bvc3Z1MUUyM0o4SE5DR1VPLUhYdyIsInkiOiJLNDlqbDFNU1A0OUo2bHhLcExpRGt4YU1ZLUVSYnZOX1NlclhqZW85SlowIiwiYWxnIjoiRVMyNTYifX0sImNvbXBhbnkiOiJVc2VyQ29ycCIsImlhdCI6MTc0NjIyMjcyNywidmN0IjoidXJuOmV1LmV1cm9wYS5lYy5ldWRpOnBkYTE6MSJ9.NoLijxtEQVO9mZRK4b6vSb5jdcggQ5X8so8K9XKy8uOtDnSMQssGg0Y-YLKO-EcLH6IA1GacbSlJtl39IeESMg~WyJRd2xtMU4tQXBLOUlEQUxSZ25kM0dnIiwiY3JlZGVudGlhbF9ob2xkZXIiLCJOaWtvcyBUZXN0b3BvdWxvcyJd~WyJtdjVGT09SbDF3ZXZWQnRQR2t4NkdBIiwiY29tcGV0ZW50X2luc3RpdHV0aW9uIiwiRU9QWVkiXQ~eyJraWQiOiJ3YWxsZXQta2V5IiwidHlwIjoia2Irand0IiwiYWxnIjoiRVMyNTYifQ.eyJzZF9oYXNoIjoiUmlrT1ExeUk2VDlQamVEd0MzdFFHV3lwU1lrbUNySHN4aXpvY0w2VmRBWSIsImF1ZCI6Imh0dHBzOi8vdmVyaWZpZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE3NDYyMjQ1MjQsIm5vbmNlIjoiZTJjMWQ4ZjEtZmZjMS00NDEyLTg3MWQtOTRhNGJjMTRhNmI1In0.4EeRKGOA5Kbr0UeOkhW6e5yft4Z785DefnLfnDf-6S21a9-3nCo3Rbvl_TRhOr-yB_dRp_h2bUafVtbQItelwg
```

💡 Paste it on https://www.sdjwt.co for inspection.

#### QR code and Button URL

Sample (demo):
```
openid4vp://?client_id=verifier-backend.eudiw.cgn&request_uri=http%3A%2F%2F192.168.1.65%3A9002%2Fverifier%2Frequest-object%2Fd2858230-7302-489a-9c24-09728d4fe2f3/
```


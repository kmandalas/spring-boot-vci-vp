## VCI

### Wallet-Initiated Issuance after Installation 

The End-User installs a new Wallet and opens it. The Wallet offers the End-User a selection of Credentials that the End-User may obtain from a Credential Issuer, e.g. a national identity Credential, a mobile driving license, or a public transport ticket. The corresponding Credential Issuers (and their URLs) are pre-configured by the Wallet or follow some discovery processes that are out of scope for this specification. By clicking on one of these options corresponding to the Credentials available for issuance, the issuance process starts using a flow supported by the Credential Issuer (Pre-Authorized Code flow or Authorization Code flow).

Wallet Providers may also provide a market place where Issuers can register to be found for Wallet-initiated flows.

References:
- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-wallet-initiated-issuance-a
- https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow

## VP

### Same Device Flow (our demo) 🧪

```
sequenceDiagram
participant UA as User Agent
participant W as Wallet
participant V as Verifier
participant VE as Verifier Endpoint

    UA ->> V: Trigger presentation
    V ->> VE: Initiate transaction
    VE -->> V: Authorization request as request_uri
    V -->> UA: Render request as deep link
    UA ->> W: Trigger wallet and pass request
    W ->> V: Get authorization request via request_uri
    V -->> W: authorization_request
    W ->> W: Parse authorization request
    alt opt
        W ->> V: Get presentation definition
        V -->> W: presentation_definition
    end
    W ->> W: Prepare response
    W ->> V: Post vp_token response
    V ->> VE: Validate response and prepare response_code
    VE -->> V: Return redirect_uri with response_code
    V -->> UA: Refresh user agent to follow redirect_uri
    UA ->> W: Follow redirect_uri passing response_code
    W ->> V: Get wallet response passing response_code
    V ->> VE: Validate response_code matches wallet response
    VE -->> V: Return wallet response
    V -->> UA: Render wallet response
```

![vp-same-device-flow.png](vp-same-device-flow.png)

### Cross Device Flow (OpenID4VP Draft) 📝
Below is a diagram of a flow where the End-User presents a Credential to a Verifier interacting with the End-User on a different device as the device the Wallet resides on.

In this flow, the Verifier prepares an Authorization Request and renders it as a QR Code. The End-User then uses the Wallet to scan the QR Code. The Verifiable Presentations are sent to the Verifier in a direct HTTP POST request to a URL controlled by the Verifier. The flow uses the Response Type vp_token in conjunction with the Response Mode direct_post, both defined in this specification. In order to keep the size of the QR Code small and be able to sign and optionally encrypt the Request Object, the actual Authorization Request contains just a Request URI according to [RFC9101], which the wallet uses to retrieve the actual Authorization Request data.

Note: The diagram does not illustrate all the optional features of this specification.

Note: The usage of the Request URI as defined in [RFC9101] does not depend on any other choices made in the protocol extensibility points, i.e., it can be used in the Same Device Flow, too.

```
+--------------+   +--------------+                                    +--------------+
|   End-User   |   |   Verifier   |                                    |    Wallet    |
|              |   |  (device A)  |                                    |  (device B)  |
+--------------+   +--------------+                                    +--------------+
|                 |                                                   |
|    Interacts    |                                                   |
|---------------->|                                                   |
|                 |  (1) Authorization Request                        |
|                 |      (Request URI)                                |
|                 |-------------------------------------------------->|
|                 |                                                   |
|                 |  (2) Request the Request Object                   |
|                 |<--------------------------------------------------|
|                 |                                                   |
|                 |  (2.5) Respond with the Request Object            |
|                 |      (Presentation Definition)                    |
|                 |-------------------------------------------------->|
|                 |                                                   |
|   End-User Authentication / Consent                                 |
|                 |                                                   |
|                 |  (3)   Authorization Response as HTTP POST        |
|                 |  (VP Token with Verifiable Presentation(s))       |
|                 |<--------------------------------------------------|
Figure 2: Cross Device Flow
```

(1) The Verifier sends to the Wallet an Authorization Request that contains a Request URI from where to obtain the Request Object containing Authorization Request parameters.

(2) The Wallet sends an HTTP GET request to the Request URI to retrieve the Request Object.

(2.5) The HTTP GET response returns the Request Object containing Authorization Request parameters. It especially contains a Presentation Definition as defined in [DIF.PresentationExchange] that describes the requirements of the Credential(s) that the Verifier is requesting to be presented. Such requirements could include what type of Credential(s), in what format(s), which individual Claims within those Credential(s) (Selective Disclosure), etc. The Wallet processes the Request Object and determines what Credentials are available matching the Verifier's request. The Wallet also authenticates the End-User and gathers her consent to present the requested Credentials.

(3) The Wallet prepares the Verifiable Presentation(s) of the Verifiable Credential(s) that the End-User has consented to. It then sends to the Verifier an Authorization Response where the Verifiable Presentation(s) are contained in the vp_token parameter.

References:
- https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-cross-device-flow

### Input Descriptor samples

#### Presentation definition

Sample (small):
```json
{
	"id": "3ea5f6db-8273-47a1-8b51-1dc8cc2a32af",
	"name": "Person Identification Data (PID)",
	"purpose": "",
	"format": {
		"vc+sd-jwt": {
			"sd-jwt_alg_values": [
				"ES256",
				"ES384"
			],
			"kb-jwt_alg_values": [
				"ES256",
				"ES384"
			]
		}
	},
	"constraints": {
		"fields": [
			{
				"path": [
					"$.vct"
				],
				"filter": {
					"type": "string",
					"const": "urn:eu.europa.ec.eudi:pid:1"
				}
			},
			{
				"path": [
					"$.given_name"
				],
				"intent_to_retain": false
			},
			{
				"path": [
					"$.age_in_years"
				],
				"intent_to_retain": false
			}
		]
	}
}
```

Sample (realistic):

Signed JWT with Header:

```json
{
  "kid": "did:web:did-doc-dts-preview.s3.eu-central-1.amazonaws.com:606a7acb-521f-44e1-8874-2caffbc31254#018f7268-5245-744e-a386-ee09c1a4fe57",
  "alg": "EdDSA"
}
```
and Payload:
```json
{
  "response_uri": "https://openid.pre.vc-dts.sicpa.com/verification/callback",
  "aud": "https://self-issued.me/v2",
  "client_id_scheme": "did",
  "iss": "did:web:did-doc-dts-preview.s3.eu-central-1.amazonaws.com:606a7acb-521f-44e1-8874-2caffbc31254",
  "response_type": "vp_token",
  "presentation_definition": {
    "id": "3b9fa10e-c7ee-459f-8ab1-d64d726453be",
    "input_descriptors": [
      {
        "id": "a53f531e-5b9a-41d9-bfb9-ecab2b12a9d1",
        "constraints": {
          "fields": [
            {
              "path": [
                "$.vct"
              ],
              "optional": false,
              "filter": {
                "type": "string",
                "const": "eu.europa.ec.eudi.photoid.1"
              }
            },
            {
              "path": [
                "$.photoid.travel_document_number"
              ],
              "optional": false
            },
            {
              "path": [
                "$.iso23220.family_name_latin1"
              ],
              "optional": false
            },
            {
              "path": [
                "$.iso23220.given_name_latin1"
              ],
              "optional": false
            },
            {
              "path": [
                "$.iso23220.birth_date"
              ],
              "optional": false
            },
            {
              "path": [
                "$.iso23220.sex"
              ],
              "optional": false
            },
            {
              "path": [
                "$.iso23220.portrait"
              ],
              "optional": false
            },
            {
              "path": [
                "$.iso23220.issuing_country"
              ],
              "optional": false
            },
            {
              "path": [
                "$.iso23220.expiry_date"
              ],
              "optional": false
            },
            {
              "path": [
                "$.iso23220.nationality"
              ],
              "optional": false
            }
          ],
          "limit_disclosure": "required"
        },
        "purpose": "Choose a valid Photo ID document."
      },
      {
        "id": "a53f531e-5b9a-41d9-bfb9-ecab2b12a9d12",
        "constraints": {
          "fields": [
            {
              "path": [
                "$.vct"
              ],
              "optional": false,
              "filter": {
                "type": "string",
                "const": "eu.europa.ec.eudi.pcd.1"
              }
            },
            {
              "path": [
                "$.phone"
              ],
              "optional": false
            },
            {
              "path": [
                "$.email_address"
              ],
              "optional": false
            },
            {
              "path": [
                "$.city_address"
              ],
              "optional": false
            },
            {
              "path": [
                "$.country_address"
              ],
              "optional": false
            },
            {
              "path": [
                "$.street_address"
              ],
              "optional": false
            }
          ],
          "limit_disclosure": "required"
        },
        "purpose": "Choose a self-issued credential with personal details verification."
      }
    ],
    "format": {
      "vc+sd-jwt": {
        "sd-jwt_alg_values": [
          "ES256"
        ],
        "kb-jwt_alg_values": [
          "ES256"
        ]
      }
    }
  },
  "state": "7fd5c3ca-eb6c-4333-8910-b04089488c1a",
  "nonce": "r13WcJ76PpsLKXYCJ0R4",
  "client_id": "did:web:did-doc-dts-preview.s3.eu-central-1.amazonaws.com:606a7acb-521f-44e1-8874-2caffbc31254",
  "client_metadata": {
    "client_name": "Hotel Benidorm",
    "logo_uri": "https://ewc.pre.vc-dts.sicpa.com/logo2.png",
    "subject_syntax_types_supported": [
      "did:indy",
      "did:v1",
      "did:ion",
      "did:ebsi",
      "did:key",
      "did:web",
      "did:ethr",
      "did:pkh",
      "did:jwk",
      "did:cheqd",
      "did:webs",
      "did:dns",
      "did:kscirc",
      "did:ling",
      "did:webvh",
      "did:iden3"
    ],
    "vp_formats": {
      "jwt_vc_json": {
        "alg": [
          "RS256",
          "RS384",
          "RS512",
          "PS256",
          "PS384",
          "PS512",
          "ES256",
          "ES256K",
          "ES384",
          "ES512",
          "EdDSA",
          "Ed25519",
          "Ed448"
        ]
      },
      "jwt_vp_json": {
        "alg": [
          "RS256",
          "RS384",
          "RS512",
          "PS256",
          "PS384",
          "PS512",
          "ES256",
          "ES256K",
          "ES384",
          "ES512",
          "EdDSA",
          "Ed25519",
          "Ed448"
        ]
      },
      "ldp_vc": {
        "proof_type": [
          "Ed25519Signature2018",
          "EcdsaSecp256k1Signature2019"
        ]
      },
      "ldp_vp": {
        "proof_type": [
          "Ed25519Signature2018",
          "EcdsaSecp256k1Signature2019"
        ]
      },
      "vc+sd-jwt": {
        "sd-jwt_alg_values": [
          "RS256",
          "RS384",
          "RS512",
          "PS256",
          "PS384",
          "PS512",
          "ES256",
          "ES256K",
          "ES384",
          "ES512",
          "EdDSA",
          "Ed25519",
          "Ed448"
        ],
        "kb-jwt_alg_values": [
          "RS256",
          "RS384",
          "RS512",
          "PS256",
          "PS384",
          "PS512",
          "ES256",
          "ES256K",
          "ES384",
          "ES512",
          "EdDSA",
          "Ed25519",
          "Ed448"
        ]
      }
    }
  },
  "response_mode": "direct_post"
}
```

#### Transaction log
```json
{
  "key": "response",
  "value": {
    "transaction_id": "nRj36W91eXAZmQElcZY_PHaz8oIfh_zmFmby1J9Oa8fh0oKgtOp6JDXA0Skk_VNACpvRDuGy-AN94n8JD9SAzg",
    "client_id": "verifier-backend.eudiw.dev",
    "request_uri": "https://verifier-backend.eudiw.dev/wallet/request.jwt/d6jziviaFApxxLl05zO3BsKpHfG6NrySAKoaOdSPiFISzrxTOvrIzYe-MU7APHGm8n5nJEoPbfDku9m00-QX5A",
    "presentation_id": "nRj36W91eXAZmQElcZY_PHaz8oIfh_zmFmby1J9Oa8fh0oKgtOp6JDXA0Skk_VNACpvRDuGy-AN94n8JD9SAzg"
  }
}
```

#### QR code and Button URL

Sample 1:
```
eudi-openid4vp://?client_id=verifier-backend.eudiw.dev&request_uri=https%3A%2F%2Fverifier-backend.eudiw.dev%2Fwallet%2Frequest.jwt%2Fd6jziviaFApxxLl05zO3BsKpHfG6NrySAKoaOdSPiFISzrxTOvrIzYe-MU7APHGm8n5nJEoPbfDku9m00-QX5A
```

Sample 2:
```
openid4vp://?client_id=did:web:did-doc-dts-preview.s3.eu-central-1.amazonaws.com:606a7acb-521f-44e1-8874-2caffbc31254&request_uri=https://openid.pre.vc-dts.sicpa.com/jwts/TosScFwdF04Y2iGZhzlm
```


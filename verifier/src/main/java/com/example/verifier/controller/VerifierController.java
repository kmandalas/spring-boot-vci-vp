package com.example.verifier.controller;

import com.authlete.sd.SDJWT;
import com.example.verifier.config.AppConfig;
import com.example.verifier.service.AuthleteHelper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
@RequestMapping("/verifier")
public class VerifierController {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, String> requestStore = new HashMap<>(); // Temporary in-memory storage for request_uri

    private final AuthleteHelper authleteHelper;
    private final AppConfig appConfig;

    public VerifierController(AuthleteHelper authleteHelper, AppConfig appConfig) {
        this.authleteHelper = authleteHelper;
        this.appConfig = appConfig;
    }

    @GetMapping("/invoke-wallet")
    public ResponseEntity<String> invokeWalletPage() {
        try {
            // Step 1: Generate a unique requestId
            String requestId = UUID.randomUUID().toString();
            String requestUri = appConfig.getRequestUriStore() + requestId;

            // Step 2: Create Authorization Request with Nested Presentation Definition
            // client_id = Verifier identifier (URI or DID). This value must be present in "sub" field of the VP JWT.
            Map<String, Object> authorizationRequest = Map.of(
                    "client_id", "verifier-backend.eudiw.cgn",
                    "response_type", "vp_token",
                    "response_mode", "direct_post",
                    "response_uri", appConfig.getResponseUri(),
                    "nonce", "abc123",
                    "presentation_definition", Map.of(
                            "id", "presentation-definition-1",
                            "name", "Portable Document A1 (PDA1)",
                            "purpose", "Demo data sharing requirements",
                            "input_descriptors", List.of(
                                    Map.of(
                                            "id", "input-descriptor-1",
                                            "format", Map.of(
                                                    "vc+sd-jwt", Map.of("alg", List.of("ES256"))
                                            ),
                                            "constraints", Map.of(
                                                    "fields", List.of(
                                                            Map.of(
                                                                    "path", List.of("$.vct"),
                                                                    "optional", "false",
                                                                    "filter", Map.of(
                                                                            "type", "string",
                                                                            "const", "urn:eu.europa.ec.eudi:pda1:1"
                                                                    )
                                                            ),
                                                            Map.of(
                                                                    "path", List.of("$.credential_holder"),
                                                                    "optional", "false"
                                                            ),
                                                            Map.of(
                                                                    "path", List.of("$.nationality"),
                                                                    "optional", "false"
                                                            ),
                                                            Map.of(
                                                                    "path", List.of("$.competent_institution"),
                                                                    "optional", "false"
                                                            )
                                                    )
                                            )
                                    )
                            )
                    ),
                    "client_metadata", Map.of(
                            "client_name", "Demo Verifier Inc.",
                            "logo_uri", "https://img.freepik.com/premium-vector/creative-logo-design-real-estate-company-vector-illustration_1253202-20005.jpg?semt=ais_hybrid&w=120"
                    )
            );

            // Step 3: Store the request in-memory (so the wallet can retrieve it)
            requestStore.put(requestId, objectMapper.writeValueAsString(authorizationRequest));

            // Step 4: Generate the deep link for wallets
            String deepLink = appConfig.getDeepLinkPrefix() + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);

            // Step 5: Return an HTML page with the QR code & deep link button
            return ResponseEntity.ok("""
                <html>
                <head>
                    <title>Cognity VCI-VP demo</title>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
                    <style>
                        body {
                            text-align: center;
                            font-family: Arial, sans-serif;
                        }
                        #qrcode {
                            display: flex;
                            justify-content: center;
                            margin: 20px auto;
                        }
                        .wallet-link {
                            display: inline-block;
                            padding: 10px 20px;
                            background-color: #007bff;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                            font-size: 16px;
                        }
                        .wallet-link:hover {
                            background-color: #0056b3;
                        }
                    </style>
                </head>
                <body>
                    <h2>Cognity VCI-VP demo</h2>
                    <p>Scan the QR code below with your phone</p>
                    <div id="qrcode"></div>
                    <p>- OR -</p>
                    <a href="%s" class="wallet-link">OPEN WITH YOUR WALLET</a>
                    <script>
                        const deepLink = "%s";
                        new QRCode(document.getElementById("qrcode"), deepLink);
                    </script>
                </body>
                </html>
                """.formatted(deepLink, deepLink));

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error generating wallet page: " + e.getMessage());
        }
    }

    /**
     * Serves pre-stored Presentation Definitions (for Cross-Device Flow?)
     */
    @GetMapping("/request-object/{requestId}")
    public ResponseEntity<String> getRequestObject(@PathVariable String requestId) {
        String requestData = requestStore.get(requestId);
        if (requestData == null) {
            return ResponseEntity.status(404).body("Request Object Not Found");
        }
        return ResponseEntity.ok(requestData);
    }

    /**
     * Endpoint for verifying a received VP Token
     */
    @PostMapping("/verify-vp")
    public ResponseEntity<String> verifyVP(@RequestBody Map<String, String> requestBody) {
        try {
            String vpToken = requestBody.get("vp_token");

            if (vpToken == null || vpToken.isEmpty()) {
                return ResponseEntity.badRequest().body("❌ No VP Token provided.");
            }

            boolean isValid = validateVPResponse(vpToken);
            extractDisclosedClaims(vpToken);
            return isValid ? ResponseEntity.ok("✅ VP Token is valid!") : ResponseEntity.badRequest().body("❌ VP Token validation failed!");

        } catch (Exception e) {
            return ResponseEntity.status(500).body("❌ Error during VP verification: " + e.getMessage());
        }
    }

    /**
     * Validates the VP Token by verifying both the SD-JWT Credential and the Key Binding JWT
     */
    private boolean validateVPResponse(String vpToken) {
        try {
            // Step 1: Parse the VP Token
            SDJWT vp = SDJWT.parse(vpToken);

            // Step 2: Fetch Issuer’s Public Key (for SD-JWT validation)
            // Could be also retrieved from "iss" claim of the payload
            JWKSet issuerJwkSet = JWKSet.load(new URL(appConfig.getIssuerJwksUrl()));
            JWK issuerPublicKey = issuerJwkSet.getKeys().get(0);

            // Step 3: do verify
            authleteHelper.verifyVP(vp, issuerPublicKey);
            return true; // Both signatures are valid
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void extractDisclosedClaims(String sdJwt) throws Exception {
        System.out.println("\nDecoding and verifying SD-JWT...");

        // Step 1: Split into JWT and disclosures
        String[] parts = sdJwt.split("~", -1);
        if (parts.length < 1) {
            throw new IllegalArgumentException("Invalid SD-JWT format");
        }

        String jwtPart = parts[0];
        List<String> disclosures = Arrays.stream(parts)
                .skip(1)
                .filter(d -> !d.isEmpty())
                .toList();

        System.out.println("Parsed JWT Part: " + jwtPart);
        System.out.println("Disclosures Count: " + disclosures.size());

        // Step 2: Decode Disclosures Safely
        System.out.println("Disclosed Claims:");
        for (String disclosure : disclosures) {
            if (disclosure.contains(".")) {
                System.out.println("Skipping JWT-style disclosure: " + disclosure);
                continue; // Ignore JWS-style disclosures
            }

            try {
                byte[] decodedBytes = Base64.getUrlDecoder().decode(disclosure);
                String decodedJson = new String(decodedBytes);
                List<String> claimData = objectMapper.readValue(decodedJson, new TypeReference<>() {});

                if (claimData.size() >= 3) {
                    String claimName = claimData.get(1);
                    String claimValue = claimData.get(2);
                    System.out.println(" - " + claimName + ": " + claimValue);
                } else {
                    System.out.println(" - Malformed disclosure: " + decodedJson);
                }
            } catch (IllegalArgumentException e) {
                System.out.println("❌ Error decoding disclosure: " + disclosure);
                e.printStackTrace();
            }
        }
    }

}


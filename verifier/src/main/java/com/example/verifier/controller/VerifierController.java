package com.example.verifier.controller;

import com.authlete.sd.SDJWT;
import com.example.verifier.config.AppConfig;
import com.example.verifier.service.AuthleteHelper;
import com.example.verifier.service.PresentationRequestService;
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

    private final AuthleteHelper authleteHelper;
    private final AppConfig appConfig;
    private final PresentationRequestService presentationRequestService;

    public VerifierController(AuthleteHelper authleteHelper, AppConfig appConfig,
                              PresentationRequestService presentationRequestService) {
        this.authleteHelper = authleteHelper;
        this.appConfig = appConfig;
        this.presentationRequestService = presentationRequestService;
    }

    /**
     * Generates an HTML page with QR code and deep links to invoke a wallet for credential presentation.
     *
     * <p>This endpoint initiates the OpenID4VP (Verifiable Presentation) flow by:
     * <ol>
     *   <li>Building a DCQL query requesting specific claims from a PDA1 credential</li>
     *   <li>Generating an ephemeral encryption key pair for VP response encryption</li>
     *   <li>Creating a signed JWT Authorization Request (JAR) with x5c certificate chain</li>
     *   <li>Storing the request for later retrieval by the wallet</li>
     *   <li>Returning an HTML page with QR code and deep links (haip-vp:// and openid4vp://)</li>
     * </ol>
     *
     * <p>The wallet retrieves the signed authorization request via {@code /request-object/{requestId}},
     * verifies the JAR signature using the x5c certificate, and submits the encrypted VP response
     * to {@code /verify-vp/{requestId}}.
     *
     * @return HTML page containing QR code and wallet invocation links
     * @see #getRequestObject(String) for JAR retrieval
     * @see #verifyVP(String, String) for VP token verification
     */
    @GetMapping("/invoke-wallet")
    public ResponseEntity<String> invokeWalletPage() {
        try {
            // DCQL query for PDA1 credential
            Map<String, Object> dcqlQuery = Map.of(
                    "credentials", List.of(
                            Map.of(
                                    "id", "pda1_credential",
                                    "format", "dc+sd-jwt",
                                    "meta", Map.of(
                                            "vct_values", List.of("urn:eu.europa.ec.eudi:pda1:1")
                                    ),
                                    "claims", List.of(
                                            Map.of("path", List.of("credential_holder")),
                                            Map.of("path", List.of("nationality")),
                                            Map.of("path", List.of("competent_institution"))
                                    )
                            )
                    )
            );

            // Base client metadata (encryption params added by service)
            Map<String, Object> clientMetadata = Map.of(
                    "client_name", "Demo Verifier Inc.",
                    "logo_uri", "https://img.freepik.com/premium-vector/creative-logo-design-real-estate-company-vector-illustration_1253202-20005.jpg?semt=ais_hybrid&w=120",
                    "purpose", "Verify your Portable Document A1 credentials"
            );

            // Generate requestId upfront so we can include it in response_uri
            String requestId = UUID.randomUUID().toString();
            String responseUriWithId = appConfig.getResponseUri() + "/" + requestId;

            // Create presentation request (generates ephemeral encryption key + signs as JAR)
            presentationRequestService.createPresentationRequest(
                    requestId,
                    responseUriWithId,
                    dcqlQuery,
                    clientMetadata
            );

            // Build request URI for wallet to fetch signed authorization request
            String requestUri = appConfig.getRequestUriStore() + requestId;

            // Get x509_hash client_id from the signing service
            String clientId = presentationRequestService.getClientId();

            // Generate deep links for both schemes (HAIP and OpenID4VP)
            String queryParams = "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                    + "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
            String haipDeepLink = "haip-vp://" + queryParams;
            String openid4vpDeepLink = "openid4vp://" + queryParams;

            // Return an HTML page with QR code (HAIP) & both deep link buttons
            return ResponseEntity.ok("""
                <html>
                <head>
                    <title>Demo Verifier Inc. VCI-VP demo</title>
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
                            margin: 5px;
                            background-color: #007bff;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                            font-size: 16px;
                        }
                        .wallet-link:hover {
                            background-color: #0056b3;
                        }
                        .wallet-link.haip {
                            background-color: #28a745;
                        }
                        .wallet-link.haip:hover {
                            background-color: #1e7e34;
                        }
                        .scheme-label {
                            font-size: 12px;
                            color: #666;
                            margin-top: 10px;
                        }
                    </style>
                </head>
                <body>
                    <h2>Cognity VCI-VP demo</h2>
                    <p>Scan the QR code below with your phone</p>
                    <p class="scheme-label">QR Code uses <code>haip-vp://</code> scheme (HAIP compliant)</p>
                    <div id="qrcode"></div>
                    <p>- OR -</p>
                    <a href="%s" class="wallet-link haip">HAIP WALLET</a>
                    <a href="%s" class="wallet-link">OpenID4VP WALLET</a>
                    <script>
                        const deepLink = "%s";
                        new QRCode(document.getElementById("qrcode"), deepLink);
                    </script>
                </body>
                </html>
                """.formatted(haipDeepLink, openid4vpDeepLink, haipDeepLink));

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error generating wallet page: " + e.getMessage());
        }
    }

    /**
     * Serves the signed Authorization Request Object as JWT (JAR).
     * Content-Type: application/oauth-authz-req+jwt
     */
    @GetMapping(value = "/request-object/{requestId}", produces = "application/oauth-authz-req+jwt")
    public ResponseEntity<String> getRequestObject(@PathVariable String requestId) {
        String signedJwt = presentationRequestService.getAuthorizationRequest(requestId);
        if (signedJwt == null) {
            return ResponseEntity.status(404).body("Request Object Not Found");
        }
        return ResponseEntity.ok(signedJwt);
    }

    /**
     * Endpoint for receiving encrypted VP Token (direct_post.jwt response mode).
     * The requestId in the path identifies which ephemeral key to use for decryption.
     * Accepts application/x-www-form-urlencoded as per OpenID4VP spec.
     */
    @PostMapping(value = "/verify-vp/{requestId}", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<String> verifyVP(@PathVariable String requestId,
                                           @RequestParam(value = "response", required = false) String encryptedResponse) {
        try {
            // With direct_post.jwt, the wallet sends "response" (JWE) instead of "vp_token"
            String vpToken;

            if (encryptedResponse != null && !encryptedResponse.isEmpty()) {
                // Decrypt the JWE response
                String decryptedPayload = presentationRequestService.decryptVpResponse(requestId, encryptedResponse);

                // Parse the decrypted payload to extract vp_token
                Map<String, Object> responsePayload = objectMapper.readValue(decryptedPayload, new TypeReference<>() {});
                vpToken = extractVpToken(responsePayload.get("vp_token"));

                if (vpToken == null) {
                    return ResponseEntity.badRequest().body("❌ No vp_token in decrypted response.");
                }

                // State is optional - log if present but don't validate
                Object state = responsePayload.get("state");
                if (state != null) {
                    System.out.println("Received state: " + state);
                }
            } else {
                return ResponseEntity.badRequest().body("❌ No encrypted response provided.");
            }

            boolean isValid = validateVPResponse(vpToken);
            extractDisclosedClaims(vpToken);

            // Cleanup the request after processing
            presentationRequestService.removeRequest(requestId);

            return isValid ? ResponseEntity.ok("✅ VP Token is valid!") : ResponseEntity.badRequest().body("❌ VP Token validation failed!");

        } catch (Exception e) {
            return ResponseEntity.status(500).body("❌ Error during VP verification: " + e.getMessage());
        }
    }

    /**
     * Extracts the VP token from various formats:
     * - String: plain vp_token (backward compatibility)
     * - Map: DCQL format {"credentialId": ["vpToken1", ...]}
     */
    @SuppressWarnings("unchecked")
    private String extractVpToken(Object vpTokenObj) {
        if (vpTokenObj == null) {
            return null;
        }

        // String format (backward compatibility)
        if (vpTokenObj instanceof String) {
            return (String) vpTokenObj;
        }

        // DCQL format: Map<QueryId, List<VP>>
        if (vpTokenObj instanceof Map) {
            Map<String, Object> vpTokenMap = (Map<String, Object>) vpTokenObj;
            // Get the first credential's first VP token...
            for (Object value : vpTokenMap.values()) {
                if (value instanceof List<?> vpList) {
                    if (!vpList.isEmpty() && vpList.get(0) instanceof String) {
                        return (String) vpList.get(0);
                    }
                }
            }
        }

        return null;
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


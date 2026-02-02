package com.example.verifier.controller;

import com.example.verifier.config.AppConfig;
import com.example.verifier.service.PresentationRequestService;
import com.example.verifier.service.VpValidationService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/verifier")
public class VerifierController {

    private static final Logger logger = LoggerFactory.getLogger(VerifierController.class);

    private final ObjectMapper objectMapper;
    private final AppConfig appConfig;
    private final PresentationRequestService presentationRequestService;
    private final VpValidationService vpValidationService;

    public VerifierController(ObjectMapper objectMapper,
                              AppConfig appConfig,
                              PresentationRequestService presentationRequestService,
                              VpValidationService vpValidationService) {
        this.objectMapper = objectMapper;
        this.appConfig = appConfig;
        this.presentationRequestService = presentationRequestService;
        this.vpValidationService = vpValidationService;
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
                        new QRCode(document.getElementById("qrcode"), {
                            text: deepLink,
                            width: 256,
                            height: 256,
                            correctLevel: QRCode.CorrectLevel.L
                        });
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
            if (encryptedResponse == null || encryptedResponse.isEmpty()) {
                return ResponseEntity.badRequest().body("❌ No encrypted response provided.");
            }

            // Decrypt the JWE response
            String decryptedPayload = presentationRequestService.decryptVpResponse(requestId, encryptedResponse);

            // Parse the decrypted payload to extract vp_token
            Map<String, Object> responsePayload = objectMapper.readValue(decryptedPayload, new TypeReference<>() {});

            // State is optional - log if present but don't validate
            Object state = responsePayload.get("state");
            if (state != null) {
                logger.debug("Received state: {}", state);
            }

            String vpToken = vpValidationService.extractVpToken(responsePayload.get("vp_token"));

            if (vpToken == null) {
                return ResponseEntity.badRequest().body("❌ No vp_token in decrypted response.");
            }

            // Validate VP and extract claims
            VpValidationService.ValidationResult result = vpValidationService.validateAndExtract(vpToken);

            // Cleanup the request after processing
            presentationRequestService.removeRequest(requestId);

            if (result.valid()) {
                String claimsJson = objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(result.disclosedClaims());
                logger.info("VP verified - issuer='{}', disclosed claims:\n{}", result.issuer(), claimsJson);
                return ResponseEntity.ok("✅ VP Token is valid!");
            } else {
                return ResponseEntity.badRequest().body("❌ VP Token validation failed: " + result.error());
            }

        } catch (Exception e) {
            return ResponseEntity.status(500).body("❌ Error during VP verification: " + e.getMessage());
        }
    }

}


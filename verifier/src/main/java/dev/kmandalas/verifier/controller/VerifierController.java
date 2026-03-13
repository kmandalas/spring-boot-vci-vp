package dev.kmandalas.verifier.controller;

import dev.kmandalas.verifier.config.AppConfig;
import dev.kmandalas.verifier.model.CredentialFormat;
import dev.kmandalas.verifier.model.PresentationRequest;
import dev.kmandalas.verifier.service.PresentationRequestService;
import dev.kmandalas.verifier.service.VpValidationService;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Controller
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
     * Renders the verifier selection page.
     */
    @GetMapping({"/select", "/invoke-wallet"})
    public String selectPage() {
        return "verifier";
    }

    /**
     * HTMX endpoint — creates a presentation request and returns the QR/deep-link fragment.
     * Only called when the user explicitly clicks "Request Presentation" (lazy creation).
     *
     * <p>This endpoint initiates the OpenID4VP (Verifiable Presentation) flow by:
     * <ol>
     *   <li>Building a DCQL query requesting specific claims from a PDA1 credential</li>
     *   <li>Generating an ephemeral encryption key pair for VP response encryption</li>
     *   <li>Creating a signed JWT Authorization Request (JAR) with x5c certificate chain</li>
     *   <li>Storing the request for later retrieval by the wallet</li>
     *   <li>Returning an HTMX fragment with QR code and deep links (haip-vp:// and openid4vp://)</li>
     * </ol>
     *
     * <p>The wallet retrieves the signed authorization request via {@code /request-object/{requestId}},
     * verifies the JAR signature using the x5c certificate, and submits the encrypted VP response
     * to {@code /verify-vp/{requestId}}.
     *
     * @param format the credential format ({@code dc+sd-jwt} or {@code mso_mdoc})
     * @param model  the Thymeleaf model for the QR fragment
     * @return the {@code fragments/qr-fragment} template name
     * @see #getRequestObject(String) for JAR retrieval
     * @see #verifyVP(String, String) for VP token verification
     */
    @GetMapping("/qr-fragment")
    public String qrFragment(@RequestParam(defaultValue = "dc+sd-jwt") String format, Model model) throws Exception {
        CredentialFormat credentialFormat = CredentialFormat.fromValue(format);
        if (credentialFormat == null) {
            credentialFormat = CredentialFormat.DC_SD_JWT;
        }

        Map<String, Object> dcqlQuery = buildDcqlQuery(credentialFormat);

        var meta = appConfig.getClientMetadata();
        String purposeSuffix = credentialFormat == CredentialFormat.MSO_MDOC ? " (mDoc)" : "";
        Map<String, Object> clientMetadata = new java.util.LinkedHashMap<>();
        clientMetadata.put("client_name", meta.getClientName());
        if (meta.getLogoUri() != null) {
            clientMetadata.put("logo_uri", meta.getLogoUri());
        }
        clientMetadata.put("purpose", meta.getPurpose() + purposeSuffix);

        String requestId = UUID.randomUUID().toString();
        String responseUriWithId = appConfig.getResponseUri() + "/" + requestId;

        presentationRequestService.createPresentationRequest(
                requestId, responseUriWithId, dcqlQuery, clientMetadata
        );

        String requestUri = appConfig.getRequestUriStore() + requestId;
        String clientId = presentationRequestService.getClientId();

        String queryParams = "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
        String haipDeepLink = "haip-vp://" + queryParams;
        String openid4vpDeepLink = "openid4vp://" + queryParams;

        boolean isMdoc = credentialFormat == CredentialFormat.MSO_MDOC;
        model.addAttribute("haipDeepLink", haipDeepLink);
        model.addAttribute("openid4vpDeepLink", openid4vpDeepLink);
        model.addAttribute("formatLabel", isMdoc ? "mDoc" : "SD-JWT");
        model.addAttribute("formatBadgeClass", isMdoc ? "format-badge-mdoc" : "format-badge-sdjwt");
        model.addAttribute("formatValue", credentialFormat.value());
        model.addAttribute("credentialDoctype", "eu.europa.ec.eudi.pda1.1");
        model.addAttribute("requestId", requestId);

        logger.info("Created presentation request {} for format {}", requestId, credentialFormat.value());

        return "fragments/qr-fragment";
    }

    /**
     * Serves the signed Authorization Request Object as JWT (JAR).
     * Content-Type: application/oauth-authz-req+jwt
     */
    @ResponseBody
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
    @ResponseBody
    @PostMapping(value = "/verify-vp/{requestId}", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<String> verifyVP(@PathVariable String requestId,
                                           @RequestParam(value = "response", required = false) String encryptedResponse) {
        try {
            if (encryptedResponse == null || encryptedResponse.isEmpty()) {
                return ResponseEntity.badRequest().body("No encrypted response provided.");
            }

            String decryptedPayload = presentationRequestService.decryptVpResponse(requestId, encryptedResponse);

            Map<String, Object> responsePayload = objectMapper.readValue(decryptedPayload, new TypeReference<>() {});

            Object state = responsePayload.get("state");
            if (state != null) {
                logger.debug("Received state: {}", state);
            }

            String vpToken = vpValidationService.extractVpToken(responsePayload.get("vp_token"));

            if (vpToken == null) {
                return ResponseEntity.badRequest().body("No vp_token in decrypted response.");
            }

            PresentationRequest request = presentationRequestService.getRequest(requestId);

            VpValidationService.ValidationResult result = vpValidationService.validateAndExtract(vpToken, request);

            // Store result for UI polling before cleanup
            presentationRequestService.storeResult(requestId, result);
            presentationRequestService.removeRequest(requestId);

            if (result.valid()) {
                String claimsJson = objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(result.disclosedClaims());
                logger.info("VP verified - issuer='{}', disclosed claims:\n{}", result.issuer(), claimsJson);
                return ResponseEntity.ok("VP Token is valid!");
            } else {
                return ResponseEntity.badRequest().body("VP Token validation failed: " + result.error());
            }

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error during VP verification: " + e.getMessage());
        }
    }

    /**
     * HTMX polling endpoint — returns the VP verification result when available.
     * Returns 204 (no content) while waiting; HTMX keeps polling.
     * Returns the result fragment when available; polling stops because the replacement has no trigger.
     */
    @GetMapping("/result/{requestId}")
    public Object vpResult(@PathVariable String requestId, Model model) {
        VpValidationService.ValidationResult result = presentationRequestService.getResult(requestId);
        if (result == null) {
            return ResponseEntity.noContent().build();
        }

        model.addAttribute("valid", result.valid());
        model.addAttribute("issuer", result.issuer());
        model.addAttribute("error", result.error());

        if (result.disclosedClaims() != null) {
            try {
                model.addAttribute("claimsJson", objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(result.disclosedClaims()));
            } catch (Exception e) {
                model.addAttribute("claimsJson", result.disclosedClaims().toString());
            }
        }

        return "fragments/result-fragment";
    }

    private Map<String, Object> buildDcqlQuery(CredentialFormat format) {
        if (format == CredentialFormat.MSO_MDOC) {
            return Map.of(
                    "credentials", List.of(
                            Map.of(
                                    "id", "pda1_mdoc",
                                    "format", CredentialFormat.MSO_MDOC.value(),
                                    "meta", Map.of(
                                            "doctype_value", "eu.europa.ec.eudi.pda1.1"
                                    ),
                                    "claims", List.of(
                                            Map.of("path", List.of("eu.europa.ec.eudi.pda1.1", "credential_holder"), "intent_to_retain", false),
                                            Map.of("path", List.of("eu.europa.ec.eudi.pda1.1", "competent_institution"), "intent_to_retain", false)
                                    )
                            )
                    )
            );
        }
        return Map.of(
                "credentials", List.of(
                        Map.of(
                                "id", "pda1_credential",
                                "format", CredentialFormat.DC_SD_JWT.value(),
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
    }

}

package dev.kmandalas.qtspmock.controller;

import dev.kmandalas.qtspmock.service.KeyManagementService;
import dev.kmandalas.qtspmock.service.KeyManagementService.ManagedCredential;
import dev.kmandalas.qtspmock.service.SadService;
import dev.kmandalas.qtspmock.service.SigningService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.*;

@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    private static final Logger logger = LoggerFactory.getLogger(DashboardController.class);

    private final KeyManagementService keyManagementService;
    private final SadService sadService;
    private final SigningService signingService;

    public DashboardController(KeyManagementService keyManagementService, SadService sadService,
                                SigningService signingService) {
        this.keyManagementService = keyManagementService;
        this.sadService = sadService;
        this.signingService = signingService;
    }

    @GetMapping
    public String dashboard(Model model) {
        List<Map<String, Object>> credentials = new ArrayList<>();
        for (String id : keyManagementService.listCredentialIds()) {
            ManagedCredential cred = keyManagementService.getCredential(id);
            Map<String, Object> credMap = new LinkedHashMap<>();
            credMap.put("id", id);
            credMap.put("subjectDN", cred.userCertificate().getSubjectX500Principal().getName());
            credMap.put("issuerDN", cred.userCertificate().getIssuerX500Principal().getName());
            credMap.put("notBefore", cred.userCertificate().getNotBefore());
            credMap.put("notAfter", cred.userCertificate().getNotAfter());
            credMap.put("algorithm", "EC P-256");
            credMap.put("scal", "2");

            if (cred.publicKey() instanceof ECPublicKey ecKey) {
                credMap.put("publicKeyX", Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(ecKey.getW().getAffineX().toByteArray()));
                credMap.put("publicKeyY", Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(ecKey.getW().getAffineY().toByteArray()));
            }

            credentials.add(credMap);
        }
        model.addAttribute("credentials", credentials);
        return "dashboard";
    }

    /**
     * Combined authorize + sign in one click for the demo UI.
     * Internally: issue SAD → immediately consume it → sign the hash.
     */
    @PostMapping("/authorize-and-sign")
    public String authorizeAndSign(@RequestParam("credentialId") String credentialId,
                                    @RequestParam("dataToSign") String dataToSign,
                                    Model model) {

        ManagedCredential credential = keyManagementService.getCredential(credentialId);
        if (credential == null) {
            model.addAttribute("error", "Credential not found: " + credentialId);
            return "fragments/sign-result";
        }

        // Step 1: Authorize (issue SAD)
        String sad = sadService.issueSad(credentialId);
        logger.info("🎫 Dashboard: issued SAD for credential {}", credentialId);

        // Step 2: Consume SAD (single-use validation)
        String validatedId = sadService.validateAndConsume(sad, credentialId);
        if (validatedId == null) {
            model.addAttribute("error", "SAD validation failed");
            return "fragments/sign-result";
        }

        // Step 3: Sign the hash
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dataToSign.getBytes(StandardCharsets.UTF_8));
            String hashBase64 = Base64.getEncoder().encodeToString(hash);

            String signature = signingService.signHash(credential.privateKey(), hash);

            model.addAttribute("success", true);
            model.addAttribute("sad", sad);
            model.addAttribute("dataToSign", dataToSign);
            model.addAttribute("hashBase64", hashBase64);
            model.addAttribute("signature", signature);
            logger.info("✍️ Dashboard: signed data for credential {}", credentialId);
        } catch (Exception e) {
            model.addAttribute("error", "Signing failed: " + e.getMessage());
        }

        return "fragments/sign-result";
    }

}

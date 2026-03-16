package dev.kmandalas.trustvalidator.controller;

import dev.kmandalas.trustvalidator.model.TrustRequestTO;
import dev.kmandalas.trustvalidator.model.VerificationContextTO;
import dev.kmandalas.trustvalidator.service.TrustValidationService;
import dev.kmandalas.trustvalidator.model.ErrorResponseTO;
import dev.kmandalas.trustvalidator.model.TrustResponseTO;
import dev.kmandalas.trustvalidator.util.X509Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@Controller
public class TrustValidatorUiController {

    private static final Logger log = LoggerFactory.getLogger(TrustValidatorUiController.class);

    private final TrustValidationService service;

    public TrustValidatorUiController(TrustValidationService service) {
        this.service = service;
    }

    @GetMapping("/")
    public String redirectToValidate() {
        return "redirect:/validate";
    }

    @GetMapping("/validate")
    public String showForm(Model model) {
        model.addAttribute("verificationContexts", Arrays.stream(VerificationContextTO.values()).map(Enum::name).toList());
        return "trust-validator-certificate-check-form";
    }

    @PostMapping("/validate")
    public String submitForm(
            @RequestParam(required = false) String chain,
            @RequestParam(required = false) String verificationContext,
            @RequestParam(required = false) String useCase,
            Model model
    ) {
        model.addAttribute("verificationContexts", Arrays.stream(VerificationContextTO.values()).map(Enum::name).toList());
        model.addAttribute("chain", chain);
        model.addAttribute("selectedContext", verificationContext);
        model.addAttribute("useCase", useCase != null ? useCase : "");

        if (chain == null || chain.isBlank()) {
            model.addAttribute("success", false);
            model.addAttribute("messageKey", "trust.validator.result.error.invalidInput");
            model.addAttribute("messageArgs", "Certificate chain must not be empty");
            return "trust-validator-certificate-check-form";
        }

        // Parse cert chain from one-per-line base64 DER
        List<String> certChain;
        try {
            certChain = Arrays.stream(chain.split("\\r?\\n"))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList();
            if (certChain.isEmpty()) throw new IllegalArgumentException("No certificates found");
        } catch (Exception e) {
            model.addAttribute("success", false);
            model.addAttribute("messageKey", "trust.validator.result.error.invalidInput");
            model.addAttribute("messageArgs", e.getMessage());
            return "trust-validator-certificate-check-form";
        }

        VerificationContextTO contextTO;
        try {
            contextTO = VerificationContextTO.valueOf(verificationContext);
        } catch (Exception e) {
            model.addAttribute("success", false);
            model.addAttribute("messageKey", "trust.validator.result.error.invalidInput");
            model.addAttribute("messageArgs", "Invalid verification context: " + verificationContext);
            return "trust-validator-certificate-check-form";
        }

        var request = new TrustRequestTO(certChain, contextTO, useCase);
        var result = service.validate(request);

        switch (result) {
            case TrustResponseTO r -> {
                model.addAttribute("success", r.trusted());
                if (r.trusted()) {
                    model.addAttribute("messageKey", "trust.validator.result.success.trusted");
                    model.addAttribute("trustAnchorCertificate", r.trustAnchor());
                } else {
                    model.addAttribute("messageKey", "trust.validator.result.error.notTrusted");
                }
            }
            case ErrorResponseTO.ClientError e -> {
                model.addAttribute("success", false);
                model.addAttribute("messageKey", "trust.validator.result.error.invalidInput");
                model.addAttribute("messageArgs", e.description());
            }
            case ErrorResponseTO.ServerError e -> {
                model.addAttribute("success", false);
                model.addAttribute("messageKey", "trust.validator.result.error.fromService");
                model.addAttribute("messageArgs", e.description());
            }
            default -> {
                model.addAttribute("success", false);
                model.addAttribute("messageKey", "trust.validator.result.error.fromService");
                model.addAttribute("messageArgs", "Unexpected error");
            }
        }

        return "trust-validator-certificate-check-form";
    }
}

package dev.kmandalas.trustvalidator.controller;

import dev.kmandalas.trustvalidator.model.ErrorResponseTO;
import dev.kmandalas.trustvalidator.model.TrustRequestTO;
import dev.kmandalas.trustvalidator.model.TrustResponseTO;
import dev.kmandalas.trustvalidator.service.TrustValidationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/trust")
public class TrustController {

    private final TrustValidationService service;

    public TrustController(TrustValidationService service) {
        this.service = service;
    }

    /**
     * POST /trust — validate an X.509 certificate chain for a given verification context.
     */
    @PostMapping(consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> checkTrust(@RequestBody TrustRequestTO request) {
        var result = service.validate(request);
        return switch (result) {
            case TrustResponseTO r -> ResponseEntity.ok(r);
            case ErrorResponseTO.ClientError e -> ResponseEntity.badRequest().body(e);
            case ErrorResponseTO.ServerError e -> ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e);
            default -> ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Unexpected result");
        };
    }
}

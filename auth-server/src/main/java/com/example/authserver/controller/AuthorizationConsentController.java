package com.example.authserver.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.*;

@Controller
public class AuthorizationConsentController {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationConsentController.class);

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final OAuth2AuthorizationService authorizationService;

    public AuthorizationConsentController(RegisteredClientRepository registeredClientRepository,
                                          OAuth2AuthorizationConsentService authorizationConsentService,
                                          OAuth2AuthorizationService authorizationService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
        this.authorizationService = authorizationService;
    }

    @GetMapping(value = "/oauth2/consent")
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(name = OAuth2ParameterNames.SCOPE, required = false) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode) {

        logger.info("Consent page requested - clientId: '{}', scope: '{}', state: '{}', principal: '{}'",
                clientId, scope, state, principal.getName());

        // PAR scope enrichment: When scope is empty but state exists, look up the stored PAR authorization
        String effectiveScope = scope;
        if (!StringUtils.hasText(scope) && StringUtils.hasText(state)) {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    state, new OAuth2TokenType(OAuth2ParameterNames.STATE));
            if (authorization != null) {
                OAuth2AuthorizationRequest storedRequest =
                        authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
                if (storedRequest != null && storedRequest.getScopes() != null && !storedRequest.getScopes().isEmpty()) {
                    effectiveScope = String.join(" ", storedRequest.getScopes());
                    logger.info("PAR: Retrieved scope from stored authorization: '{}'", effectiveScope);
                }
            }
        }

        // Remove scopes that were already approved
        Set<String> scopesToApprove = new HashSet<>();
        Set<String> previouslyApprovedScopes = new HashSet<>();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        logger.debug("RegisteredClient lookup - found: {}, internalId: {}",
                registeredClient != null, registeredClient != null ? registeredClient.getId() : "N/A");

        OAuth2AuthorizationConsent currentAuthorizationConsent =
                this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());
        Set<String> authorizedScopes;
        if (currentAuthorizationConsent != null) {
            authorizedScopes = currentAuthorizationConsent.getScopes();
        } else {
            authorizedScopes = Collections.emptySet();
        }
        for (String requestedScope : StringUtils.delimitedListToStringArray(effectiveScope, " ")) {
            if (OidcScopes.OPENID.equals(requestedScope)) {
                continue;
            }
            if (authorizedScopes.contains(requestedScope)) {
                previouslyApprovedScopes.add(requestedScope);
            } else {
                scopesToApprove.add(requestedScope);
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("state", state);
        model.addAttribute("scopes", withDescription(scopesToApprove));
        model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("userCode", userCode);
        if (StringUtils.hasText(userCode)) {
            model.addAttribute("requestURI", "/oauth2/device_verification");
        } else {
            model.addAttribute("requestURI", "/oauth2/authorize");
        }

        logger.debug("Rendering consent page - clientId in model: '{}', state in model: '{}', scopesToApprove: {}",
                clientId, state, scopesToApprove);

        return "consent";
    }

    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> scopeWithDescriptions = new HashSet<>();
        for (String scope : scopes) {
            scopeWithDescriptions.add(new ScopeWithDescription(scope));
        }
        return scopeWithDescriptions;
    }

    public static class ScopeWithDescription {
        private static final String DEFAULT_DESCRIPTION = "UNKNOWN SCOPE - We cannot provide information about this permission.";
        private static final Map<String, String> scopeDescriptions = new HashMap<>();

        static {
            scopeDescriptions.put(
                    OidcScopes.PROFILE,
                    "This application will be able to read your profile information."
            );
            scopeDescriptions.put(
                    "eu.europa.ec.eudi.pda1.1",
                    "Issue a Portable Document A1 (PDA1) credential - Social security coordination document for cross-border workers. Claims: Credential Holder & Competent Institution."
            );
        }

        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
        }
    }

}

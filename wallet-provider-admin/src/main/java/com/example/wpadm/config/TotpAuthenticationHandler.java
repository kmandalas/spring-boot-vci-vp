package com.example.wpadm.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;

/**
 * Handles post-password authentication flow for TOTP-based MFA.
 *
 * After successful username/password authentication:
 * - Redirects to /totp/verify if TOTP is already configured
 * - Redirects to /setup-totp if TOTP needs to be set up
 *
 * Also provides grantTotpFactor() to add the TOTP authority after successful
 * TOTP verification, enabling access to MFA-protected resources.
 */
@Component
public class TotpAuthenticationHandler implements AuthenticationSuccessHandler {

    public static final String TOTP_AUTHORITY = "FACTOR_TOTP";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        if (authentication.getPrincipal() instanceof AdminUserDetails adminUser) {
            if (adminUser.isTotpEnabled()) {
                // User has TOTP enabled - redirect to verification
                response.sendRedirect("/totp/verify");
            } else {
                // User doesn't have TOTP configured yet - redirect to setup
                response.sendRedirect("/setup-totp");
            }
        } else {
            // Fallback - should not happen with proper UserDetailsService
            response.sendRedirect("/login?error=true");
        }
    }

    /**
     * Grants the TOTP factor authority to the current authentication.
     * Call this after successful TOTP code verification.
     *
     * This updates the SecurityContext with a new Authentication object
     * that includes the FACTOR_TOTP authority, enabling access to
     * MFA-protected resources.
     */
    public void grantTotpFactor() {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        if (currentAuth == null) {
            return;
        }

        var authorities = new ArrayList<GrantedAuthority>(currentAuth.getAuthorities());
        authorities.add(FactorGrantedAuthority.fromFactor("TOTP"));

        var newAuth = new UsernamePasswordAuthenticationToken(
                currentAuth.getPrincipal(),
                currentAuth.getCredentials(),
                authorities
        );

        SecurityContextHolder.getContext().setAuthentication(newAuth);
    }
}

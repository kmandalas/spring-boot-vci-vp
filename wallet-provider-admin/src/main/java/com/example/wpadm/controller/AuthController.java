package com.example.wpadm.controller;

import com.example.wpadm.config.AdminUserDetails;
import com.example.wpadm.config.TotpAuthenticationHandler;
import com.example.wpadm.service.TotpService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AuthController {

    private final TotpService totpService;
    private final TotpAuthenticationHandler totpAuthHandler;

    public AuthController(TotpService totpService, TotpAuthenticationHandler totpAuthHandler) {
        this.totpService = totpService;
        this.totpAuthHandler = totpAuthHandler;
    }

    @GetMapping("/login")
    public String loginPage(@RequestParam(required = false) String error,
                           @RequestParam(required = false) String logout,
                           @RequestParam(required = false) String expired,
                           Model model) {
        if (error != null) {
            model.addAttribute("error", "Invalid username or password");
        }
        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully");
        }
        if (expired != null) {
            model.addAttribute("error", "Your session has expired. Please login again.");
        }
        return "auth/login";
    }

    /**
     * TOTP verification page - shown when user has TOTP already configured.
     * Authorization is handled by Spring Security (requires PASSWORD_AUTHORITY).
     */
    @GetMapping("/totp/verify")
    public String totpPage(@AuthenticationPrincipal AdminUserDetails adminUser, Model model) {
        model.addAttribute("username", adminUser.getUsername());
        return "auth/totp";
    }

    /**
     * Verify TOTP code for login.
     * On success, grants TOTP factor authority enabling access to protected resources.
     */
    @PostMapping("/totp/verify")
    public String verifyTotp(@RequestParam String code,
                            @AuthenticationPrincipal AdminUserDetails adminUser,
                            Model model) {
        if (totpService.verifyCode(adminUser.getUserId(), code)) {
            // Grant TOTP factor - enables access to MFA-protected resources
            totpAuthHandler.grantTotpFactor();
            return "redirect:/dashboard";
        }

        model.addAttribute("error", "Invalid verification code. Please try again.");
        model.addAttribute("username", adminUser.getUsername());
        return "auth/totp";
    }

    /**
     * TOTP setup page - shown when user doesn't have TOTP configured yet.
     * Authorization is handled by Spring Security (requires PASSWORD_AUTHORITY).
     */
    @GetMapping("/setup-totp")
    public String setupTotpPage(@AuthenticationPrincipal AdminUserDetails adminUser, Model model) {
        // Generate new TOTP setup data
        var setupData = totpService.generateSetupData(adminUser.getUserId(), adminUser.getUsername());
        model.addAttribute("qrCodeUri", setupData.qrCodeUri());
        model.addAttribute("secret", setupData.secret());
        model.addAttribute("username", adminUser.getUsername());
        return "auth/setup-totp";
    }

    /**
     * Verify TOTP code during initial setup and enable 2FA.
     * On success, grants TOTP factor authority enabling access to protected resources.
     */
    @PostMapping("/setup-totp/verify")
    public String verifyAndEnableTotp(@RequestParam String code,
                                      @AuthenticationPrincipal AdminUserDetails adminUser,
                                      RedirectAttributes redirectAttributes) {
        if (totpService.verifyAndEnable(adminUser.getUserId(), code)) {
            // Grant TOTP factor - enables access to MFA-protected resources
            totpAuthHandler.grantTotpFactor();
            redirectAttributes.addFlashAttribute("success", "Two-factor authentication has been enabled!");
            return "redirect:/dashboard";
        }

        redirectAttributes.addFlashAttribute("error", "Invalid verification code. Please try again.");
        return "redirect:/setup-totp";
    }
}

package com.example.wpadm.controller;

import com.example.wpadm.config.AdminUserDetails;
import com.example.wpadm.model.WuaView;
import com.example.wpadm.service.WuaAdminService;
import com.example.wpadm.util.WuaDisplayUtils;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.UUID;

/**
 * WUA management controller - requires FACTOR_TOTP authority (handled by SecurityConfig).
 */
@Controller
@RequestMapping("/wua")
public class WuaController {

    private final WuaAdminService wuaAdminService;

    public WuaController(WuaAdminService wuaAdminService) {
        this.wuaAdminService = wuaAdminService;
    }

    /**
     * Add WuaDisplayUtils to all views in this controller.
     */
    @ModelAttribute
    public void addDisplayUtils(Model model) {
        model.addAttribute("wuaUtils", new WuaDisplayUtilsWrapper());
    }

    /**
     * Wrapper class to expose WuaDisplayUtils static methods to Thymeleaf.
     */
    public static class WuaDisplayUtilsWrapper {
        public String formatWscdType(String wscdType) {
            return WuaDisplayUtils.formatWscdType(wscdType);
        }

        public String formatSecurityLevel(String securityLevel) {
            return WuaDisplayUtils.formatSecurityLevel(securityLevel);
        }

        public String toIso18045Level(String wscdType) {
            return WuaDisplayUtils.toIso18045Level(wscdType);
        }

        public String getWscdBadgeClass(String wscdType) {
            return WuaDisplayUtils.getWscdBadgeClass(wscdType);
        }

        public String getSecurityBadgeClass(String securityLevel) {
            return WuaDisplayUtils.getSecurityBadgeClass(securityLevel);
        }

        public String getWscdIcon(String wscdType) {
            return WuaDisplayUtils.getWscdIcon(wscdType);
        }
    }

    @GetMapping
    public String listWuas(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String wscdType,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal AdminUserDetails adminUser,
            Model model) {

        List<WuaView> wuas = wuaAdminService.findWuas(status, wscdType, search, page, size);
        long totalCount = wuaAdminService.countWuas(status, wscdType, search);
        int totalPages = (int) Math.ceil((double) totalCount / size);

        model.addAttribute("wuas", wuas);
        model.addAttribute("statuses", List.of("ACTIVE", "REVOKED"));
        model.addAttribute("wscdTypes", wuaAdminService.getDistinctWscdTypes());
        model.addAttribute("currentStatus", status);
        model.addAttribute("currentWscdType", wscdType);
        model.addAttribute("search", search);
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", totalPages);
        model.addAttribute("totalCount", totalCount);
        model.addAttribute("activePage", "wua");
        model.addAttribute("username", adminUser.getUsername());
        return "wua/list";
    }

    @GetMapping("/{wuaId}")
    public String viewWua(@PathVariable UUID wuaId,
                         @AuthenticationPrincipal AdminUserDetails adminUser,
                         Model model) {

        WuaView wua = wuaAdminService.findById(wuaId)
            .orElseThrow(() -> new IllegalArgumentException("WUA not found: " + wuaId));

        model.addAttribute("wua", wua);
        model.addAttribute("activePage", "wua");
        model.addAttribute("username", adminUser.getUsername());
        return "wua/detail";
    }

    @GetMapping("/{wuaId}/revoke")
    public String showRevokeConfirmation(@PathVariable UUID wuaId,
                                        @AuthenticationPrincipal AdminUserDetails adminUser,
                                        Model model) {

        WuaView wua = wuaAdminService.findById(wuaId)
            .orElseThrow(() -> new IllegalArgumentException("WUA not found: " + wuaId));

        if (!"ACTIVE".equals(wua.status())) {
            return "redirect:/wua/" + wuaId;
        }

        model.addAttribute("wua", wua);
        model.addAttribute("activePage", "wua");
        model.addAttribute("username", adminUser.getUsername());
        return "wua/revoke-confirm";
    }

    @PostMapping("/{wuaId}/revoke")
    public String revokeWua(@PathVariable UUID wuaId,
                           @RequestParam String reason,
                           @AuthenticationPrincipal AdminUserDetails adminUser,
                           RedirectAttributes redirectAttributes) {

        boolean success = wuaAdminService.revokeWua(wuaId, reason, adminUser.getUsername());

        if (success) {
            redirectAttributes.addFlashAttribute("success", "WUA has been revoked successfully");
        } else {
            redirectAttributes.addFlashAttribute("error", "Failed to revoke WUA");
        }

        return "redirect:/wua/" + wuaId;
    }
}

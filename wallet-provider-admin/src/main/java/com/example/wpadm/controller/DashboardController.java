package com.example.wpadm.controller;

import com.example.wpadm.config.AdminUserDetails;
import com.example.wpadm.service.WuaAdminService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Dashboard controller - requires FACTOR_TOTP authority (handled by SecurityConfig).
 */
@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    private final WuaAdminService wuaAdminService;

    public DashboardController(WuaAdminService wuaAdminService) {
        this.wuaAdminService = wuaAdminService;
    }

    @GetMapping
    public String dashboard(@AuthenticationPrincipal AdminUserDetails adminUser, Model model) {
        model.addAttribute("stats", wuaAdminService.getDashboardStats());
        model.addAttribute("recentWuas", wuaAdminService.getRecentWuas(10));
        model.addAttribute("activePage", "dashboard");
        model.addAttribute("username", adminUser.getUsername());
        return "dashboard/index";
    }
}

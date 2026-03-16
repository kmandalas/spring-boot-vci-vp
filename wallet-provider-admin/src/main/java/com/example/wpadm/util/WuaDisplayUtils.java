package com.example.wpadm.util;

/**
 * Utility class for formatting WUA display values.
 * Maps Android attestation values to ISO 18045 attack potential resistance levels.
 */
public final class WuaDisplayUtils {

    private WuaDisplayUtils() {}

    /**
     * Maps WSCD type to ISO 18045 attack potential resistance level.
     */
    public static String toIso18045Level(String wscdType) {
        if (wscdType == null) {
            return "unknown";
        }
        return switch (wscdType.toLowerCase()) {
            case "strongbox" -> "iso_18045_high";
            case "tee" -> "iso_18045_high";
            case "software" -> "iso_18045_basic";
            default -> "unknown";
        };
    }

    /**
     * Formats WSCD type for display with ISO 18045 level.
     */
    public static String formatWscdType(String wscdType) {
        if (wscdType == null) {
            return "Unknown";
        }
        return switch (wscdType.toLowerCase()) {
            case "strongbox" -> "StrongBox (Hardware)";
            case "tee" -> "TEE (Trusted Execution)";
            case "software" -> "Software";
            default -> capitalize(wscdType);
        };
    }

    /**
     * Formats security level for display with ISO 18045 level.
     */
    public static String formatSecurityLevel(String securityLevel) {
        if (securityLevel == null) {
            return "Unknown";
        }
        return switch (securityLevel.toLowerCase()) {
            case "strongbox" -> "StrongBox (ISO 18045 High)";
            case "trustedenvironment", "tee" -> "TEE (ISO 18045 High)";
            case "software" -> "Software (ISO 18045 Basic)";
            default -> capitalize(securityLevel);
        };
    }

    /**
     * Returns a badge color class based on WSCD type.
     */
    public static String getWscdBadgeClass(String wscdType) {
        if (wscdType == null) {
            return "bg-secondary";
        }
        return switch (wscdType.toLowerCase()) {
            case "strongbox" -> "bg-success";  // Green for hardware
            case "tee" -> "bg-primary";        // Blue for TEE
            case "software" -> "bg-warning text-dark";  // Yellow for software
            default -> "bg-secondary";
        };
    }

    /**
     * Returns a badge color class based on security level.
     */
    public static String getSecurityBadgeClass(String securityLevel) {
        if (securityLevel == null) {
            return "bg-secondary";
        }
        return switch (securityLevel.toLowerCase()) {
            case "strongbox" -> "bg-success";
            case "trustedenvironment", "tee" -> "bg-primary";
            case "software" -> "bg-warning text-dark";
            default -> "bg-secondary";
        };
    }

    /**
     * Returns an icon class based on WSCD type.
     */
    public static String getWscdIcon(String wscdType) {
        if (wscdType == null) {
            return "bi-question-circle";
        }
        return switch (wscdType.toLowerCase()) {
            case "strongbox" -> "bi-shield-fill-check";  // Shield with check
            case "tee" -> "bi-cpu-fill";                 // CPU for TEE
            case "software" -> "bi-code-slash";          // Code for software
            default -> "bi-question-circle";
        };
    }

    private static String capitalize(String str) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase();
    }
}

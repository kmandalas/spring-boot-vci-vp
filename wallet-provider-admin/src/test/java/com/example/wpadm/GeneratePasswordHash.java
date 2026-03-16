package com.example.wpadm;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class GeneratePasswordHash {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String hash = encoder.encode("admin123");
        System.out.println("BCrypt hash for 'admin123': " + hash);
        System.out.println("Verify: " + encoder.matches("admin123", hash));
    }
}

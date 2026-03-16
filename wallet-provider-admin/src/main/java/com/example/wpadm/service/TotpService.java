package com.example.wpadm.service;

import com.example.wpadm.repository.AdminUserRepository;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
public class TotpService {

    private final AdminUserRepository adminUserRepository;
    private final SecretGenerator secretGenerator;
    private final QrGenerator qrGenerator;
    private final CodeVerifier codeVerifier;
    private final String issuer;

    public TotpService(AdminUserRepository adminUserRepository,
                       @Value("${admin.totp.issuer:WUA Admin Console}") String issuer) {
        this.adminUserRepository = adminUserRepository;
        this.issuer = issuer;
        this.secretGenerator = new DefaultSecretGenerator();
        this.qrGenerator = new ZxingPngQrGenerator();
        this.codeVerifier = new DefaultCodeVerifier(
            new DefaultCodeGenerator(),
            new SystemTimeProvider()
        );
    }

    /**
     * Generate TOTP setup data (QR code + secret) for a user.
     */
    @Transactional
    public TotpSetupData generateSetupData(UUID userId, String username) {
        String secret = secretGenerator.generate();

        QrData data = new QrData.Builder()
            .label(username)
            .secret(secret)
            .issuer(issuer)
            .algorithm(HashingAlgorithm.SHA1)
            .digits(6)
            .period(30)
            .build();

        try {
            byte[] imageData = qrGenerator.generate(data);
            String qrCodeUri = getDataUriForImage(imageData, qrGenerator.getImageMimeType());

            // Store the secret (not yet verified/enabled)
            adminUserRepository.updateTotpSecret(userId, secret);

            return new TotpSetupData(qrCodeUri, secret);
        } catch (Exception e) {
            throw new RuntimeException("Error generating QR code", e);
        }
    }

    /**
     * Verify TOTP code and enable 2FA if valid.
     */
    @Transactional
    public boolean verifyAndEnable(UUID userId, String code) {
        return adminUserRepository.findById(userId)
            .map(user -> {
                if (user.totpSecret() != null && codeVerifier.isValidCode(user.totpSecret(), code)) {
                    adminUserRepository.enableTotp(userId);
                    return true;
                }
                return false;
            })
            .orElse(false);
    }

    /**
     * Verify TOTP code for login (user already has 2FA enabled).
     */
    public boolean verifyCode(UUID userId, String code) {
        return adminUserRepository.findById(userId)
            .filter(user -> user.totpEnabled() && user.totpSecret() != null)
            .map(user -> codeVerifier.isValidCode(user.totpSecret(), code))
            .orElse(false);
    }

    /**
     * Verify TOTP code by username for login.
     */
    public boolean verifyCodeByUsername(String username, String code) {
        return adminUserRepository.findByUsername(username)
            .filter(user -> user.totpEnabled() && user.totpSecret() != null)
            .map(user -> codeVerifier.isValidCode(user.totpSecret(), code))
            .orElse(false);
    }

    public record TotpSetupData(String qrCodeUri, String secret) {}
}

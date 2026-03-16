package dev.kmandalas.trustvalidator.model;

/**
 * Transfer object enum for the verification context, matching the EUDI VerificationContext sealed interface.
 */
public enum VerificationContextTO {
    WalletInstanceAttestation,
    WalletUnitAttestation,
    WalletUnitAttestationStatus,
    PID,
    PIDStatus,
    PubEAA,
    PubEAAStatus,
    QEAA,
    QEAAStatus,
    EAA,
    EAAStatus,
    WalletRelyingPartyRegistrationCertificate,
    WalletRelyingPartyAccessCertificate,
    QTSPSigningCertificate,
    Custom
}

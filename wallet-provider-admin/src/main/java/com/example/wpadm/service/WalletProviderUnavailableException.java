package com.example.wpadm.service;

public class WalletProviderUnavailableException extends RuntimeException {

    public WalletProviderUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}

package dev.kmandalas.walletprovider;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class WalletProviderApplication {

    public static void main(String[] args) {
        SpringApplication.run(WalletProviderApplication.class, args);
    }
}

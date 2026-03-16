package dev.kmandalas.trustvalidator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class TrustValidatorApplication {

    public static void main(String[] args) {
        SpringApplication.run(TrustValidatorApplication.class, args);
    }
}

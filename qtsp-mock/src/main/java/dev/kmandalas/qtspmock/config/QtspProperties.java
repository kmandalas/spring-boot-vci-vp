package dev.kmandalas.qtspmock.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "qtsp")
public class QtspProperties {

    private String apiKey = "qtsp-demo-api-key";
    private long sadTtlSeconds = 300; // 5 minutes

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public long getSadTtlSeconds() {
        return sadTtlSeconds;
    }

    public void setSadTtlSeconds(long sadTtlSeconds) {
        this.sadTtlSeconds = sadTtlSeconds;
    }
}

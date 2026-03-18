package com.example.wpadm.client;

import com.example.wpadm.client.dto.EventsResponse;
import com.example.wpadm.client.dto.RevocationRequest;
import com.example.wpadm.client.dto.RevocationResultDto;
import com.example.wpadm.config.WalletProviderClientProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.UUID;

@Component
@EnableConfigurationProperties(WalletProviderClientProperties.class)
public class WalletProviderAdminClient {

    private final RestClient restClient;

    public WalletProviderAdminClient(RestClient.Builder builder, WalletProviderClientProperties properties) {
        this.restClient = builder
                .baseUrl(properties.baseUrl())
                .defaultHeader("X-Admin-Api-Key", properties.apiKey())
                .build();
    }

    public EventsResponse pollEvents(long since, int limit) {
        return restClient.get()
                .uri("/wp/admin/api/v1/events?since={since}&limit={limit}", since, limit)
                .retrieve()
                .body(EventsResponse.class);
    }

    public RevocationResultDto revokeWua(UUID wuaId, String reason, String adminUser) {
        return restClient.post()
                .uri("/wp/admin/api/v1/wuas/{wuaId}/revoke", wuaId)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new RevocationRequest(reason, adminUser))
                .retrieve()
                .body(RevocationResultDto.class);
    }
}

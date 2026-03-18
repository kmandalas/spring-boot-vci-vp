package com.example.wpadm.client.dto;

import java.util.List;

public record EventsResponse(
        List<OutboxEventDto> events
) {}

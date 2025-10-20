package com.banred.ms_middleware_signcrypt.domain.event.dto;

import lombok.Data;

@Data
public class EventoInterno {
    private final String tipo;
    private final String timestamp;

    public EventoInterno(String tipo, String timestamp) {
        this.tipo = tipo;
        this.timestamp = timestamp;
    }
}

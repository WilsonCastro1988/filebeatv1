package com.banred.ms_middleware_signcrypt.model;

public class EventoInterno {
    private final String tipo;
    private final String timestamp;

    public EventoInterno(String tipo, String timestamp) {
        this.tipo = tipo;
        this.timestamp = timestamp;
    }

    public String getTipo() {
        return tipo;
    }

    public String getTimestamp() {
        return timestamp;
    }

}

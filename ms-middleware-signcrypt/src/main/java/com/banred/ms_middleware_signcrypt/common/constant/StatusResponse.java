package com.banred.ms_middleware_signcrypt.common.constant;

import lombok.Getter;

@Getter
public enum StatusResponse {
    SUCCESS("SUCCESS"),
    FAILURE("FAILURE"),
    ERROR("ERROR");

    private final String value;

    StatusResponse(String value) {
        this.value = value;
    }

    public static StatusResponse fromValue(String value) {
        for (StatusResponse tipo : values()) {
            if (tipo.value.equalsIgnoreCase(value)) {
                return tipo;
            }
        }
        throw new IllegalArgumentException("Valor desconocido: " + value);
    }
}


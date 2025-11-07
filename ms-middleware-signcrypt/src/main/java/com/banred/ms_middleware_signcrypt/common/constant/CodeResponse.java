package com.banred.ms_middleware_signcrypt.common.constant;

import lombok.Getter;

@Getter
public enum CodeResponse {
    TIMEOUTFB("8364");


    private final String value;

    CodeResponse(String value) {
        this.value = value;
    }

    public static CodeResponse fromValue(String value) {
        for (CodeResponse tipo : values()) {
            if (tipo.value.equalsIgnoreCase(value)) {
                return tipo;
            }
        }
        throw new IllegalArgumentException("Valor desconocido: " + value);
    }
}


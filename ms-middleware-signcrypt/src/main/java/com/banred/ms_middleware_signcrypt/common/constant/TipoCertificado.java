package com.banred.ms_middleware_signcrypt.common.constant;

import lombok.Getter;

@Getter
public enum TipoCertificado {
    PUBLIC("PUBLIC"),
    PRIVATE("PRIVATE"),
    PROVEEDOR("PROVEEDOR");

    private final String value;

    TipoCertificado(String value) {
        this.value = value;
    }

    public static TipoCertificado fromValue(String value) {
        for (TipoCertificado tipo : values()) {
            if (tipo.value.equalsIgnoreCase(value)) {
                return tipo;
            }
        }
        throw new IllegalArgumentException("Valor desconocido: " + value);
    }
}


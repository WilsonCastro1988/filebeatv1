package com.banred.ms_middleware_signcrypt.common.constant;

import lombok.Getter;

@Getter
public enum TipoCanal {
    IN("IN"),
    MB("MB"),
    VPN("VPN");

    private final String value;

    TipoCanal(String value) {
        this.value = value;
    }

    public static TipoCanal fromValue(String value) {
        for (TipoCanal tipo : values()) {
            if (tipo.value.equalsIgnoreCase(value)) {
                return tipo;
            }
        }
        throw new IllegalArgumentException("Valor desconocido: " + value);
    }
}


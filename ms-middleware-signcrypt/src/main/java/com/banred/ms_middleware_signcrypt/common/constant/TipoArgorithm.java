package com.banred.ms_middleware_signcrypt.common.constant;

import lombok.Getter;

@Getter
public enum TipoArgorithm {
    AES("AES"),
    RSA("RSA");

    private final String value;

    TipoArgorithm(String value) {
        this.value = value;
    }

    public static TipoArgorithm fromValue(String value) {
        for (TipoArgorithm tipo : values()) {
            if (tipo.value.equalsIgnoreCase(value)) {
                return tipo;
            }
        }
        throw new IllegalArgumentException("Valor desconocido: " + value);
    }
}


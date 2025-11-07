package com.banred.ms_middleware_signcrypt.common.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CryptoExceptionFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoExceptionFactory.class);

    private CryptoExceptionFactory() {}

    public static AbstractError createCryptoException(Exception e, String errorCode, String operation, String contextId) {
        String errorMessage = String.format("Error durante la operación de criptografía '%s' para el contexto '%s'. Causa: %s", operation, contextId, e.getMessage());
        LOGGER.error(errorMessage, e);
        return new AbstractError(errorCode, errorMessage, contextId, e);
    }
}

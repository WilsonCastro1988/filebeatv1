package com.banred.ms_middleware_signcrypt.common.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CryptoExceptionFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoExceptionFactory.class);

    // Constructor privado para evitar instanciación
    private CryptoExceptionFactory() {}

    /**
     * Crea una AbstractError a partir de una excepción técnica de criptografía.
     *
     * @param e La excepción original capturada (JOSEException, ParseException, etc.).
     * @param errorCode El código de error específico (ej. "CRYPTO_JWE_001").
     * @param operation La operación que se estaba realizando (ej. "encriptación JWE").
     * @param contextId Un identificador de contexto (ej. ID de la institución, nombre del keystore).
     * @return Una instancia de AbstractError lista para ser lanzada.
     */
    public static AbstractError createCryptoException(Exception e, String errorCode, String operation, String contextId) {
        String errorMessage = String.format("Error durante la operación de criptografía '%s' para el contexto '%s'. Causa: %s", operation, contextId, e.getMessage());
        LOGGER.error(errorMessage, e);
        return new AbstractError(errorCode, errorMessage, contextId, e);
    }
}

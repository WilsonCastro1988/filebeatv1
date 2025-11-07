package com.banred.ms_middleware_signcrypt.common.exception;

import com.banred.ms_middleware_signcrypt.common.constant.CodeResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientRequestException;

public final class WebExceptionFactory {

    private WebExceptionFactory() {
    }

    public static AbstractError mapWebClientRequestException(WebClientRequestException ex, String url) {

        String message = obtenerMensage(ex);

        if (message.contains("timeout") || message.contains("timed out")) {
            return new AbstractError(HttpStatus.REQUEST_TIMEOUT.value(),
                    CodeResponse.TIMEOUTFB.getValue(),
                    "Timeout de conexión con: " + url, "T");
        } else if (message.contains("connection refused")) {
            return new AbstractError("503", "Servicio no disponible: " + url, "T");
        } else if (message.contains("unknown host") || message.contains("nodename nor servname provided")) {
            return new AbstractError("502", "Host no encontrado: " + url, "T");
        } else if (message.contains("ssl") || message.contains("certificate")) {
            return new AbstractError("502", "Error SSL/TLS con: " + url, "T");
        } else if (message.contains("network is unreachable")) {
            return new AbstractError("503", "Red no alcanzable: " + url, "T");
        } else {
            return new AbstractError("502", "Error de conectividad con " + url + ": " + message, "T");
        }
    }

    private static String obtenerMensage(WebClientRequestException ex) {
        String message = "";

        if (ex.getMessage() != null) {
            message = ex.getMessage().toLowerCase();
        } else {
            Throwable cause = ex.getCause();
            if (cause != null) {
                if (cause.getMessage() != null) {
                    message = cause.getMessage().toLowerCase();
                } else {
                    message = cause.getClass().getSimpleName().toLowerCase();
                }
            }
        }
        return message;
    }
}

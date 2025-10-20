package com.banred.ms_middleware_signcrypt.common.exception;


public abstract class AbstractException extends RuntimeException {

    private static final long serialVersionUID = -8132295132825609981L;

    AbstractException() {
    }

    AbstractException(String mensaje) {
        super(mensaje);
    }

    AbstractException(Exception ex) {
        super(ex);
    }

    AbstractException(String message, Throwable cause) {
        super(message, cause);
    }

    AbstractException(Throwable cause) {
        super(cause);
    }

    public abstract int getCodigoHttp();

    public abstract String getTipo();
}

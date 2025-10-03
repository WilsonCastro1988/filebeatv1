package com.banred.ms_middleware_signcrypt.common.exception;


public abstract class AbstractException extends RuntimeException {

    private static final long serialVersionUID = -8132295132825609981L;

    public AbstractException() {
    }

    public AbstractException(String mensaje) {
        super(mensaje);
    }

    public AbstractException(Exception ex) {
        super(ex);
    }

    public AbstractException(String message, Throwable cause) {
        super(message, cause);
    }

    public AbstractException(Throwable cause) {
        super(cause);
    }

    public abstract int getCodigoHttp();

    public abstract String getTipo();
}

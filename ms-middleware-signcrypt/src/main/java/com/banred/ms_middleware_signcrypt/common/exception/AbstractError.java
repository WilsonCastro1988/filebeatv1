package com.banred.ms_middleware_signcrypt.common.exception;

import com.banred.ms_middleware_signcrypt.common.exception.payloads.BodyErrorAes256;
import com.banred.ms_middleware_signcrypt.common.exception.payloads.IBodyError;

public class AbstractError extends AbstractException {
    private static final String CODIGO_ERROR = "9999";
    private static final int HTTP_STATUS_CODE_BAD_REQUEST = 400;
    private static final int HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR = 500;
    private static final String TIPO_NEGOCIO = "N";
    private static final String TIPO_TECNICO = "T";
    private final transient IBodyError errorAes256;
    private final int httpStatusCode;
    private static final long serialVersionUID = 1160952182301070504L;

    public AbstractError(String codigo, String mensaje, String origen) {
        super(mensaje);
        this.errorAes256 = new BodyErrorAes256(TIPO_NEGOCIO, codigo, mensaje, "", origen);
        this.httpStatusCode = HTTP_STATUS_CODE_BAD_REQUEST;
    }

    public AbstractError(Throwable cause, String origen) {
        super(cause);
        this.errorAes256 = new BodyErrorAes256(TIPO_TECNICO, CODIGO_ERROR, cause.getMessage(), cause.toString(), origen);
        this.httpStatusCode = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }

    public AbstractError(String code, String message, String tipo, Throwable cause) {
        super(message, cause);
        this.errorAes256 = new BodyErrorAes256(TIPO_TECNICO, code, cause.getMessage(), cause.toString(), tipo);
        this.httpStatusCode = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }

    public AbstractError(Exception ex, String origen) {
        super(ex);
        this.errorAes256 = new BodyErrorAes256(TIPO_TECNICO, CODIGO_ERROR, ex.getMessage(), ex.toString(), origen);
        this.httpStatusCode = HTTP_STATUS_CODE_INTERNAL_SERVER_ERROR;
    }

    public int getCodigoHttp() {
        return this.httpStatusCode;
    }

    public String getTipo() {
        return this.errorAes256.getTipo();
    }
}

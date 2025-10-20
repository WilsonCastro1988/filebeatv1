package com.banred.ms_middleware_signcrypt.common.exception.payloads;

import java.io.Serializable;

public interface IBodyError extends Serializable{
    String getTipo();

    void setTipo(String var1);

    String getFecha();

    void setFecha(String var1);

    String getOrigen();

    void setOrigen(String var1);

    String getCodigo();

    void setCodigo(String var1);

    String getCodigoErrorExterno();

    void setCodigoErrorExterno(String var1);

    String getMensaje();

    void setMensaje(String var1);

    String getDetalle();

    void setDetalle(String var1);
}

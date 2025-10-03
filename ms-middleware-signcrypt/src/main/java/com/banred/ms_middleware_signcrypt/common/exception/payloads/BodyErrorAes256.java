package com.banred.ms_middleware_signcrypt.common.exception.payloads;

import java.text.SimpleDateFormat;
import java.util.Date;

public class BodyErrorAes256 implements IBodyError {
    private String tipo;
    private String fecha;
    private String origen;
    private String codigo;
    private String codigoErrorExterno;
    private String mensaje;
    private String detalle;

    public BodyErrorAes256() {
        this.tipo = "N";
        this.codigo = "0000";
        this.mensaje = "OK";
        this.detalle = "OK";
        this.calcularFecha();
    }

    private void calcularFecha() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSz");
        this.fecha = sdf.format(new Date());
    }

    public BodyErrorAes256(String codigo, String mensaje) {
        this.tipo = "N";
        this.codigo = codigo;
        this.mensaje = mensaje;
        this.calcularFecha();
    }

    public BodyErrorAes256(String tipo, String codigo, String mensaje) {
        this.tipo = tipo;
        this.codigo = codigo;
        this.mensaje = mensaje;
        this.calcularFecha();
    }

    public BodyErrorAes256(String tipo, String codigo, String mensaje, String detalle) {
        this.tipo = tipo;
        this.codigo = codigo;
        this.mensaje = mensaje;
        this.detalle = detalle;
        this.calcularFecha();
    }

    public BodyErrorAes256(String tipo, String codigo, String mensaje, String detalle, String origen) {
        this.tipo = tipo;
        this.codigo = codigo;
        this.mensaje = mensaje;
        this.detalle = detalle;
        this.origen = origen;
        this.calcularFecha();
    }

    public String getCodigo() {
        return this.codigo;
    }

    public String getCodigoErrorExterno() {
        return this.codigoErrorExterno;
    }

    public String getDetalle() {
        return this.detalle;
    }

    public String getFecha() {
        return this.fecha;
    }

    public String getMensaje() {
        return this.mensaje;
    }

    public String getOrigen() {
        return this.origen;
    }

    public String getTipo() {
        return this.tipo;
    }

    public void setCodigo(String codigo) {
        this.codigo = codigo;
    }

    public void setCodigoErrorExterno(String codigoErrorExterno) {
        this.codigoErrorExterno = codigoErrorExterno;
    }

    public void setDetalle(String detalle) {
        this.detalle = detalle;
    }

    public void setFecha(String fecha) {
        this.fecha = fecha;
    }

    public void setMensaje(String mensaje) {
        this.mensaje = mensaje;
    }

    public void setOrigen(String origen) {
        this.origen = origen;
    }

    public void setTipo(String tipo) {
        this.tipo = tipo;
    }
}

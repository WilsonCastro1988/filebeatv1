package com.banred.ms_middleware_signcrypt.common.exception.payloads;

import lombok.Getter;
import lombok.Setter;

import java.text.SimpleDateFormat;
import java.util.Date;

@Setter
@Getter
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

}

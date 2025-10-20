package com.banred.ms_middleware_signcrypt.domain.jw.service.rsa;


import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;

public interface IRsa {
    String cifrar(String textPlano, String keybase64) throws AbstractException;

    String descifrar(String base64CipherText, String keybase64) throws AbstractException;

    String getPrivateKey(String canal, String codCliente, String tipo, String path) throws AbstractException;

    String getPublicKey(String canal, String codCliente, String tipo, String path) throws AbstractException;


}

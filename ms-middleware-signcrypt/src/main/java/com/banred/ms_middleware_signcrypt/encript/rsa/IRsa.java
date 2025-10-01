package com.banred.ms_middleware_signcrypt.encript.rsa;


import com.banred.ms_middleware_signcrypt.encript.exceptions.AbstractException;

public interface IRsa  {
    String cifrar(String textPlano, String keybase64) throws AbstractException;

    String descifrar(String base64CipherText, String keybase64) throws AbstractException;

}

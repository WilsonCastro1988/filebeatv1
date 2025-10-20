package com.banred.ms_middleware_signcrypt.domain.jw.service.aes256;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;

public interface IAes256 {
    String cifrar(String textPlano, String keybase64) throws AbstractException;

    String descifrar(String base64CipherText, String keybase64) throws AbstractException;

    String generarLlave() throws AbstractException;

}

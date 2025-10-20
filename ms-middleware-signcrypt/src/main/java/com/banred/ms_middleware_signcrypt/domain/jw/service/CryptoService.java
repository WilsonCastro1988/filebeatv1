package com.banred.ms_middleware_signcrypt.domain.jw.service;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.SecurityConfig;
import com.banred.ms_middleware_signcrypt.domain.jw.dto.JWSResponse;

public interface CryptoService {

    String sign(String payload, SecurityConfig client) throws AbstractException;

    String encrypt(String payload, Institution client) throws AbstractException;

    boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws AbstractException;

    String decrypt(String jweCompact, Institution client) throws AbstractException;

    JWSResponse signWithHeaders(String payload, Institution client) throws AbstractException;

    void verifyWithHeaders(String jwsCompact, String digestHeader, String signatureInput, Institution institution) throws AbstractException;


}

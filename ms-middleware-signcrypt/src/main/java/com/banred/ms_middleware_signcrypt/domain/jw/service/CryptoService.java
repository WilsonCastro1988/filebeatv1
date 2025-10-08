package com.banred.ms_middleware_signcrypt.domain.jw.service;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.SecurityConfig;
import com.banred.ms_middleware_signcrypt.domain.jw.dto.JWSResponse;

public interface CryptoService {

    String sign(String payload, SecurityConfig client) throws Exception;

    String encrypt(String payload, Institution client) throws Exception;

    boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws Exception;

    String decrypt(String jweCompact, Institution client) throws Exception;

    JWSResponse signWithHeaders(String payload, Institution client) throws Exception;

    void verifyWithHeaders(String jwsCompact, String digestHeader, String signatureInput, Institution institution) throws Exception;


}

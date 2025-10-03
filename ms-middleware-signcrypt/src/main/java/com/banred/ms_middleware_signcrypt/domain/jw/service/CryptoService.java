package com.banred.ms_middleware_signcrypt.domain.jw.service;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.SecurityConfig;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface CryptoService {

    String sign(String payload, SecurityConfig client) throws Exception;

    String encrypt(String payload, Institution client) throws Exception;

    boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws Exception;

    String decrypt(String jweCompact, Institution client) throws Exception;

    String encryptData(String payload) throws Exception;

}

package com.banred.ms_middleware_signcrypt.service;

import com.banred.ms_middleware_signcrypt.model.SecurityConfig;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface CryptoService {

    String sign(String payload, SecurityConfig jwsConfig) throws Exception;

    String encrypt(String payload, SecurityConfig jweConfig) throws Exception;

    PrivateKey loadPrivateKey(SecurityConfig config) throws Exception;

    X509Certificate loadCertificate(SecurityConfig config) throws Exception;

    boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws Exception;

    String decrypt(String jweCompact, SecurityConfig jweConfig) throws Exception;

    String encryptData(String payload) throws Exception;

}

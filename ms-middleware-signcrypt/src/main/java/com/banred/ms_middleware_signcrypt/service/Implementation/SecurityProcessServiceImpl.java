package com.banred.ms_middleware_signcrypt.service.Implementation;


import com.banred.ms_middleware_signcrypt.model.SecurityConfig;
import com.banred.ms_middleware_signcrypt.service.SecurityProcessService;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Service
public class SecurityProcessServiceImpl implements SecurityProcessService {

    public String sign(String payload, SecurityConfig jwsConfig) throws Exception {
        PrivateKey privateKey = loadPrivateKey(jwsConfig);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setAlgorithmHeaderValue("RS256");
        jws.setKey(privateKey);

        return jws.getCompactSerialization();
    }

    public String encrypt(String payload, SecurityConfig jweConfig) throws Exception {
        X509Certificate cert = loadCertificate(jweConfig);

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(payload);
        jwe.setAlgorithmHeaderValue("RSA-OAEP-256");
        jwe.setEncryptionMethodHeaderParameter("A256GCM");
        jwe.setKey(cert.getPublicKey());

        return jwe.getCompactSerialization();
    }

    public PrivateKey loadPrivateKey(SecurityConfig config) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(config.getKeystore()), config.getKeystorePassword().toCharArray());
        String alias = keyStore.aliases().nextElement();
        return (PrivateKey) keyStore.getKey(alias, config.getKeystorePassword().toCharArray());
    }

    public X509Certificate loadCertificate(SecurityConfig config) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(config.getTruststore()), config.getTruststorePassword().toCharArray());
        String alias = trustStore.aliases().nextElement();
        return (X509Certificate) trustStore.getCertificate(alias);
    }
}

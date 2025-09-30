package com.banred.ms_middleware_signcrypt.service.Implementation;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.model.SecurityConfig;
import com.banred.ms_middleware_signcrypt.service.CryptoService;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class CryptoServiceImpl implements CryptoService {

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    public String encryptData(String payload) throws Exception {
        Institution institution = institutionRedisService.getInstitution(payload);
        return encrypt(payload, institution.getJwe());
    }

    public String sign(String payload, SecurityConfig jwsConfig) throws Exception {
        PrivateKey privateKey = loadPrivateKey(jwsConfig);

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                new Payload(payload)
        );

        JWSSigner signer = new RSASSASigner(privateKey);
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public boolean verify(String jwsCompact, SecurityConfig jwsConfig) throws Exception {
        PublicKey publicKey = loadCertificate(jwsConfig).getPublicKey();

        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        JWSVerifier verifier = new RSASSAVerifier((java.security.interfaces.RSAPublicKey) publicKey);
        return jwsObject.verify(verifier);
    }

    public SecretKey generateSecretKeyAES256() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // 256 bits para AES-256

        // Convertir la SECRET KEY a Base64 para su transporte seguro
        //String encodedSecretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        return keyGenerator.generateKey();
    }

    public String encrypt(String payload, SecurityConfig jweConfig) throws Exception {
        //PublicKey publicKey = loadCertificate(jweConfig).getPublicKey();
        SecretKey secretKey = generateSecretKeyAES256();
        String skEncoded = encryptSecretKey(secretKey, jweConfig);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                .type(JOSEObjectType.JWT) // Tipo de contenido
                .customParam("x-key", skEncoded) // Proteger la clave en el header
                .build();

        JWEObject jweObject = new JWEObject(header,new Payload(payload));
        JWEEncrypter encrypter = new DirectEncrypter(secretKey);
        jweObject.encrypt(encrypter);

        return jweObject.serialize();
    }

    public String decrypt(String jweCompact, SecurityConfig jweConfig) throws Exception {
        PrivateKey privateKey = loadPrivateKey(jweConfig);
        JWEObject jweObject = JWEObject.parse(jweCompact);
        JWEDecrypter decrypter = new RSADecrypter((java.security.interfaces.RSAPrivateKey) privateKey);
        jweObject.decrypt(decrypter);
        return jweObject.getPayload().toString();
    }

    public X509Certificate loadCertificate(SecurityConfig config) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(config.getKeystore()), config.getKeystorePassword().toCharArray());
        String alias = keyStore.aliases().nextElement();
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    public PrivateKey loadPrivateKey(SecurityConfig config) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(config.getKeystore()), config.getKeystorePassword().toCharArray());
        String alias = keyStore.aliases().nextElement();
        return (PrivateKey) keyStore.getKey(alias, config.getKeystorePassword().toCharArray());
    }

    private String encryptSecretKey(SecretKey secretKey, SecurityConfig config) throws Exception {
        PublicKey publicKey = loadCertificate(config).getPublicKey();
        String encodedSecretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSecretKey = cipher.doFinal(encodedSecretKey.getBytes());
        return Base64.getEncoder().encodeToString(encryptedSecretKey);
    }
}
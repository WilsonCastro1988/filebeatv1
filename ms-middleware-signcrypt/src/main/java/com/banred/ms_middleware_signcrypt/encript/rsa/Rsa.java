package com.banred.ms_middleware_signcrypt.encript.rsa;


import com.banred.ms_middleware_signcrypt.encript.exceptions.AbstractError;
import com.banred.ms_middleware_signcrypt.encript.exceptions.AbstractException;
import jakarta.inject.Singleton;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Singleton
public class Rsa implements IRsa {
    private static final Logger LOGGER = LoggerFactory.getLogger(Rsa.class);

    // Usar OAEP recomendado en lugar de PKCS1
    private static final String RSA_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String SIGN_ALGORITHM = "SHA256withRSA";

    public Rsa() {
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.info("Rsa is Ready");
    }

    public String cifrar(String textoEnClaro, String publicKey) throws AbstractException {
        if (textoEnClaro == null || textoEnClaro.isBlank()) {
            throw new AbstractError("3013", "Texto en claro vacío o nulo", "RSA.cifrar");
        }

        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(spec);

            Cipher cipher = Cipher.getInstance(RSA_CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);

            byte[] encrypted = cipher.doFinal(textoEnClaro.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            LOGGER.error("Error al cifrar con RSA", e);
            throw new AbstractError(e, "RSA.cifrar");
        }
    }

    public String descifrar(String textoCifrado, String privateKey) throws AbstractException {
        if (textoCifrado == null || textoCifrado.isBlank()) {
            throw new AbstractError("3014", "Texto cifrado vacío o nulo", "RSA.descifrar");
        }

        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(spec);

            Cipher cipher = Cipher.getInstance(RSA_CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, privKey);

            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(textoCifrado));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.error("Error al descifrar con RSA", e);
            throw new AbstractError(e, "RSA.descifrar");
        }
    }

    public String firmar(String textoEnClaro, String privateKey) throws AbstractException {
        if (textoEnClaro == null || textoEnClaro.isBlank()) {
            throw new AbstractError("3015", "Texto en claro vacío o nulo", "RSA.firmar");
        }

        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(spec);

            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initSign(privKey);
            signature.update(textoEnClaro.getBytes(StandardCharsets.UTF_8));

            byte[] signedData = signature.sign();
            return Base64.getEncoder().encodeToString(signedData);
        } catch (Exception e) {
            LOGGER.error("Error al firmar con RSA", e);
            throw new AbstractError(e, "RSA.firmar");
        }
    }
}

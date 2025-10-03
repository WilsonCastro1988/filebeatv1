package com.banred.ms_middleware_signcrypt.common.util;

import com.banred.ms_middleware_signcrypt.common.constant.TipoArgorithm;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Utilities {

    public static SecretKey fromBase64(String base64Key, String algorithm) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, algorithm);
    }


    public static PrivateKey toPrivateKey(String base64Key, String algorithm) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePrivate(keySpec);
    }


    public static PublicKey toPublicKey(String base64PublicKey, String algorithm) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }


    public static String readKeyAsBase64(Key key) throws Exception {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

}

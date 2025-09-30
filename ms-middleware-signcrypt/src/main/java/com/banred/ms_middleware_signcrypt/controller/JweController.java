package com.banred.ms_middleware_signcrypt.controller;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.model.Request;
import com.banred.ms_middleware_signcrypt.service.CryptoService;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/jwe")
public class JweController {

    @Autowired
    private CryptoService cryptoService;

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody String input) throws Exception {
        return cryptoService.encryptData(input);
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestHeader("x-key") String encryptedSecretKey, @RequestBody String encryptedJson)
            throws Exception {
        return null;
    }
}

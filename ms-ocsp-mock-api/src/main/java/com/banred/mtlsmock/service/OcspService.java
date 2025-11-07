package com.banred.mtlsmock.service;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class OcspService {

    private final PrivateKey ocspSignerKey;
    private final X509Certificate ocspSignerCert;
    private final Map<String, CertificateStatus> statusMap = new HashMap<>();

    public OcspService() throws Exception {
        X509Certificate caCert = loadCert("certs/ca/ca.crt");
        ocspSignerKey = loadPrivateKey("certs/ca/private/ca.key");
        ocspSignerCert = caCert;

        // Estados simulados
        // SERIALES FIJOS (deben coincidir con los certificados generados)
        statusMap.put("1001", CertificateStatus.GOOD);                    // cliente-valid
        statusMap.put("1002", CertificateStatus.GOOD);                    // cliente-expired
        statusMap.put("9999", new UnknownStatus());                      // cliente-unknown
        statusMap.put("8888", new RevokedStatus(new Date(), CRLReason.keyCompromise));
        Security.addProvider(new BouncyCastleProvider());
    }

    private X509Certificate loadCert(String path) throws Exception {
        try (InputStream is = new ClassPathResource(path).getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        try (InputStream is = new ClassPathResource(path).getInputStream()) {
            String pem = new String(is.readAllBytes())
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] decoded = Base64.getDecoder().decode(pem);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        }
    }

    public OCSPResp generateResponse(OCSPReq request) throws Exception {
        DigestCalculator digCalc = new JcaDigestCalculatorProviderBuilder()
                .build().get(CertificateID.HASH_SHA1);

        // CORREGIDO: Usa JcaX509CertificateHolder para extraer SubjectPublicKeyInfo
        SubjectPublicKeyInfo publicKeyInfo = new JcaX509CertificateHolder(ocspSignerCert).getSubjectPublicKeyInfo();
        RespID respID = new RespID(publicKeyInfo, digCalc);
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respID);

        boolean hasValidRequest = false;

        for (Req req : request.getRequestList()) {
            CertificateID certId = req.getCertID();
            hasValidRequest = true;

            BigInteger serial = certId.getSerialNumber();
            String key = getKeyFromSerial(serial);

            CertificateStatus status = statusMap.getOrDefault(key, new UnknownStatus());
            builder.addResponse(certId, status);
        }

        if (!hasValidRequest) {
            return new OCSPRespBuilder().build(OCSPResponseStatus.MALFORMED_REQUEST, null);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(ocspSignerKey);
        X509CertificateHolder[] chain = {new JcaX509CertificateHolder(ocspSignerCert)};
        BasicOCSPResp basicResp = builder.build(signer, chain, new Date());

        // Soporte para Nonce
        Extension nonceExt = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonceExt != null) {
            basicResp = builder.build(signer, chain, new Date());
        }

        return new OCSPRespBuilder().build(OCSPResponseStatus.SUCCESSFUL, basicResp);
    }

    private String getKeyFromSerial(BigInteger serial) {
        for (String key : statusMap.keySet()) {
            if (key.contains(serial.toString())) {
                return key;
            }
        }
        return "cliente-unknown";
    }
}

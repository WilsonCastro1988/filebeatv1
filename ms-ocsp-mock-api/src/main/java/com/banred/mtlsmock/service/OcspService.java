package com.banred.mtlsmock.service;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
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

        // Estados simulados de prueba
        statusMap.put("cliente-valid", CertificateStatus.GOOD);
        statusMap.put("cliente-expired", CertificateStatus.GOOD);
        statusMap.put("cliente-unknown", new UnknownStatus());
        statusMap.put("cliente-invalid", new RevokedStatus(
                new Date(), CRLReason.keyCompromise
        ));
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

        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(
                new RespID(ResponderID.getInstance(new X509CertificateHolder(ocspSignerCert.getEncoded()).getSubjectPublicKeyInfo()))
        );

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

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(ocspSignerKey);

        X509CertificateHolder[] chain = {new X509CertificateHolder(ocspSignerCert.getEncoded())};
        BasicOCSPResp basicResp = builder.build(signer, chain, new Date());

        Extension nonceExt = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonceExt != null) {
            builder.setResponseExtensions(new Extensions(nonceExt));
            basicResp = builder.build(signer, chain, new Date());
        }

        return new OCSPRespBuilder().build(OCSPResponseStatus.SUCCESSFUL, basicResp);
    }

    private String getKeyFromSerial(BigInteger serial) {
        // En tu implementación real podrías mapear serial -> CN o usar directamente el serial
        for (String key : statusMap.keySet()) {
            if (key.contains(serial.toString())) {
                return key;
            }
        }
        return "cliente-unknown";
    }
}

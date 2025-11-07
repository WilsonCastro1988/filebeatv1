package com.banred.ms_middleware_signcrypt.components;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

@Component
public class X509CertificateValidator {

    private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidator.class);

    @Value("${mtls.ocsp.enabled}")
    private boolean ocspEnabled;

    @Value("${mtls.ocsp.soft-fail}")
    private boolean ocspSoftFail;

    @Value("${mtls.ocsp.timeout}")
    private int ocspTimeout;

    public X509CertificateValidator() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void validateKeyStoreCertificates(final KeyStore keyStore,
                                             final KeyStore trustStore,
                                             final Institution institution) throws KeyStoreException {
        if (keyStore == null || institution == null) {
            throw new AbstractError("500", "KeyStore o institución nulos en validación mTLS", "T");
        }

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            final Certificate rawCert = keyStore.getCertificate(alias);

            if (!(rawCert instanceof X509Certificate cert)) {
                throw new AbstractError("401",
                        String.format("Certificado inválido o ausente para alias '%s' en institución '%s'", alias, institution.getId()),
                        "T");
            }

            logger.debug("Validando certificado alias='{}' subject='{}' issuer='{}'",
                    alias, cert.getSubjectX500Principal(), cert.getIssuerX500Principal());

            validateKeyUsage(cert, institution.getId(), alias);
            validateExtendedKeyUsage(cert, institution.getId(), alias);
            validateBasicConstraints(cert, institution.getId(), alias);

            if (!ocspEnabled) {
                logger.info("OCSP deshabilitado por configuración (mtls.ocsp.enabled=false)");
                return;
            }

            final X509Certificate issuerCert = getIssuerCertificate(cert, keyStore, trustStore);
            validateCertificateWithOCSP(cert, issuerCert, institution.getId(), alias);
        }
    }

    private void validateKeyUsage(final X509Certificate cert, final String institutionId, final String alias) {
        final boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage == null || !keyUsage[0]) {
            throw new AbstractError("401",
                    String.format("KeyUsage inválido: digitalSignature requerido. Institución: %s, Alias: %s", institutionId, alias),
                    "T");
        }
        logger.info("KeyUsage OK para certificado en institución {}, alias {}", institutionId, alias);
    }

    private void validateExtendedKeyUsage(final X509Certificate cert, final String institutionId, final String alias) {
        try {
            final List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
            if (extendedKeyUsage == null || !extendedKeyUsage.contains("1.3.6.1.5.5.7.3.2")) {
                throw new AbstractError("401",
                        String.format("ExtendedKeyUsage inválido: clientAuth requerido. Institución: %s, Alias: %s", institutionId, alias),
                        "T");
            }
            logger.info("ExtendedKeyUsage OK para certificado en institución {}, alias {}", institutionId, alias);
        } catch (final Exception e) {
            throw new AbstractError("401",
                    String.format("Error leyendo ExtendedKeyUsage. Institución: %s, Alias: %s, Causa: %s", institutionId, alias, e.getMessage()),
                    "T", e);
        }
    }

    private void validateBasicConstraints(final X509Certificate cert, final String institutionId, final String alias) {
        if (cert.getBasicConstraints() >= 0) {
            throw new AbstractError("401",
                    String.format("BasicConstraints inválido: certificado de cliente no debe ser CA. Institución: %s, Alias: %s", institutionId, alias),
                    "T");
        }
        logger.info("BasicConstraints OK para certificado en institución {}, alias {}", institutionId, alias);
    }

    private X509Certificate getIssuerCertificate(final X509Certificate cert, final KeyStore keyStore, final KeyStore trustStore) throws KeyStoreException {
        if (cert == null) {
            throw new IllegalArgumentException("cert null en getIssuerCertificate");
        }

        final var issuerPrincipal = cert.getIssuerX500Principal();
        if (issuerPrincipal == null) {
            throw new AbstractError("401", "Cert no contiene Issuer X500Principal: " + cert.getSubjectX500Principal(), "T");
        }

        if (trustStore != null) {
            final Enumeration<String> tAliases = trustStore.aliases();
            while (tAliases.hasMoreElements()) {
                final String a = tAliases.nextElement();
                final Certificate cand = trustStore.getCertificate(a);
                if (cand instanceof X509Certificate x509 && Objects.equals(issuerPrincipal, x509.getSubjectX500Principal())) {
                        logger.debug("Issuer encontrado en trustStore alias='{}' subject='{}'", a, x509.getSubjectX500Principal());
                        return x509;
                    }

            }
        }

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            final Certificate cand = keyStore.getCertificate(alias);
            if (cand instanceof X509Certificate x509 && Objects.equals(issuerPrincipal, x509.getSubjectX500Principal())) {
                    logger.debug("Issuer encontrado en keyStore alias='{}' subject='{}'", alias, x509.getSubjectX500Principal());
                    return x509;
                }

        }

        throw new AbstractError("401",
                String.format("Issuer no encontrado para certificado %s (issuer=%s)", cert.getSubjectX500Principal(), issuerPrincipal),
                "T");
    }

    /**
     * Valida el certificado usando OCSP con soft-fail opcional
     */
    private void validateCertificateWithOCSP(final X509Certificate cert, final X509Certificate issuerCert,
                                             final String institutionId, final String alias) {
        try {
            final String ocspUrl = getOCSPUrl(cert);
            if (ocspUrl == null || ocspUrl.trim().isEmpty()) {
                logger.warn("OCSP no configurado en AIA para certificado {}. Se permite por política.", cert.getSubjectX500Principal());
                return;
            }

            final OCSPReq request = generateOCSPRequest(issuerCert, cert.getSerialNumber());
            final byte[] responseBytes = sendOCSPRequest(ocspUrl, request.getEncoded());

            final SingleResp singleResp = getSingleResp(cert, responseBytes);
            final Object statusObj = singleResp.getCertStatus();

            if (statusObj == CertificateStatus.GOOD) {
                logger.info("OCSP: Certificado VÁLIDO. Serial: {}, Institución: {}", cert.getSerialNumber(), institutionId);
            } else if (statusObj instanceof RevokedStatus) {
                logger.error("OCSP: Certificado REVOCADO. Serial: {}, Institución: {}, Alias: {}", cert.getSerialNumber(), institutionId, alias);
                throw new AbstractError("401",
                        String.format("Certificado revocado (OCSP). Serial: %s, Institución: %s", cert.getSerialNumber(), institutionId),
                        "T");
            } else if (statusObj instanceof UnknownStatus) {
                logger.error("OCSP: Certificado DESCONOCIDO. Serial: {}, Institución: {}", cert.getSerialNumber(), institutionId);
                throw new AbstractError("401",
                        String.format("Certificado desconocido por OCSP. Serial: %s, Institución: %s", cert.getSerialNumber(), institutionId),
                        "T");
            }

        } catch (final IOException | OCSPException | OperatorCreationException e) {
            if (ocspSoftFail) {
                logger.warn("OCSP soft-fail: {}", e.getMessage());
            } else {
                throw new AbstractError("401", "OCSP hard-fail: " + e.getMessage(), "T", e);
            }
        } catch (final Exception e) {
            throw new AbstractError("401",
                    String.format("Error crítico en OCSP. Institución: %s, Alias: %s, Causa: %s", institutionId, alias, e.getMessage()),
                    "T", e);
        }
    }

    private static SingleResp getSingleResp(final X509Certificate cert, final byte[] responseBytes)
            throws IOException, OCSPException {
        final OCSPResp ocspResponse = new OCSPResp(responseBytes);

        if (ocspResponse.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
            throw new IOException("OCSP respuesta fallida. Status: " + ocspResponse.getStatus());
        }

        final BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
        if (basicResponse == null || basicResponse.getResponses() == null || basicResponse.getResponses().length == 0) {
            throw new IOException("OCSP respuesta vacía para certificado: " + cert.getSubjectX500Principal());
        }

        return basicResponse.getResponses()[0];
    }

    private String getOCSPUrl(final X509Certificate cert) throws IOException {
        final byte[] aiaExtensionValue = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
        if (aiaExtensionValue == null) {
            return null;
        }

        try (ASN1InputStream ais = new ASN1InputStream(aiaExtensionValue)) {
            final ASN1OctetString oct = ASN1OctetString.getInstance(ais.readObject());
            try (ASN1InputStream ais2 = new ASN1InputStream(oct.getOctets())) {
                final ASN1Sequence seq = (ASN1Sequence) ais2.readObject();
                final AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(seq);
                for (final AccessDescription ad : aia.getAccessDescriptions()) {
                    if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                        final GeneralName gn = ad.getAccessLocation();
                        final String raw = gn.getName().toString();
                        return raw.replaceFirst("^URIName:", "").trim();
                    }
                }
            }
        } catch (final Exception e) {
            logger.warn("Error parseando AIA/OCSP extension: {}", e.getMessage());
            return null;
        }
        return null;
    }

    private OCSPReq generateOCSPRequest(final X509Certificate issuerCert, final BigInteger serialNumber)
            throws OperatorCreationException, OCSPException, CertificateEncodingException {
        final DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder()
                .build().get(CertificateID.HASH_SHA1);

        final OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(digestCalculator,
                new JcaX509CertificateHolder(issuerCert), serialNumber));
        return builder.build();
    }

    private byte[] sendOCSPRequest(final String ocspUrl, final byte[] requestBytes) throws IOException {
        final URL url = new URL(ocspUrl);
        final HttpURLConnection con = (HttpURLConnection) url.openConnection();

        try {
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setConnectTimeout(this.ocspTimeout);
            con.setReadTimeout(this.ocspTimeout);

            try (var out = con.getOutputStream()) {
                out.write(requestBytes);
            }

            final int responseCode = con.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("OCSP HTTP error: " + responseCode + " para URL: " + ocspUrl);
            }

            try (InputStream in = con.getInputStream()) {
                return in.readAllBytes();
            }
        } finally {
            con.disconnect();
        }
    }
}

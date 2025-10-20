package com.banred.ms_middleware_signcrypt.domain.mtls.service.impl;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.components.X509CertificateValidator;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.mtls.service.WebClientService;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.handler.ssl.SslProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.Duration;

@Service
public class WebClientServiceImpl implements WebClientService {

    private static final Logger logger = LoggerFactory.getLogger(WebClientServiceImpl.class);

    private final X509CertificateValidator certificateValidator;

    public WebClientServiceImpl(X509CertificateValidator certificateValidator) {
        this.certificateValidator = certificateValidator;
    }

    @Override
    public WebClient createWebClient(Institution institution) {
        try {
            // 1. Configurar KeyStore y TrustStore
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(institution.getMtls().getKeystore());
            keyStore.load(fis, institution.getMtls().getKeystorePassword().toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, institution.getMtls().getKeystorePassword().toCharArray());

            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            fis = new FileInputStream(institution.getMtls().getTruststore());
            trustStore.load(fis, institution.getMtls().getTruststorePassword().toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            certificateValidator.validateKeyStoreCertificates(keyStore, trustStore, institution);

            certificateValidator.validateTrustStoreCertificates(trustStore, institution);

            // 2. Crear SslContext de Netty
            SslContext sslCtx = SslContextBuilder.forClient()
                    .sslProvider(SslProvider.JDK)
                    .keyManager(kmf)
                    .trustManager(tmf)
                    .build();

            HttpClient httpClient = HttpClient.create()
                    .secure(sslSpec -> sslSpec.sslContext(sslCtx))
                    .doOnConnected(conn -> conn.addHandlerLast(new ChannelInboundHandlerAdapter() {
                        @Override
                        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
                            if (evt instanceof SslHandshakeCompletionEvent handshakeEvent && !handshakeEvent.isSuccess()) {
                                throw new AbstractError("401", handshakeEvent.cause().getMessage(), "N");
                            }

                            super.userEventTriggered(ctx, evt);
                        }
                    }))
                    .responseTimeout(Duration.ofMillis(institution.getTimeout()));

            // 4. Crear WebClient
            WebClient webClient = WebClient.builder()
                    .clientConnector(new ReactorClientHttpConnector(httpClient))
                    .baseUrl(institution.getEndpoint())
                    .build();

            logger.info("WebClient con MTLS creado para institución {}", institution.getId());
            return webClient;
        } catch (IOException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException |
                 CertificateException | NoSuchProviderException e) {
            throw new AbstractError(e, "Error creando WebClient para institución");
        }
    }
}

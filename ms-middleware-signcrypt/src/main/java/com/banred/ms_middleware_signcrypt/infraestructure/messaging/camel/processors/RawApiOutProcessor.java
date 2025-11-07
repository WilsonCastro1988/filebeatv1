package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.common.constant.CodeResponse;
import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.domain.jw.dto.JWSResponse;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.nimbusds.jose.JWEObject;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.TimeoutException;

import static com.banred.ms_middleware_signcrypt.common.exception.WebExceptionFactory.mapWebClientRequestException;

@Component
public class RawApiOutProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(RawApiOutProcessor.class);

    private final CryptoService cryptoService;
    private final IInstitutionRedisService institutionRedisService;

    public RawApiOutProcessor(CryptoService cryptoService, IInstitutionRedisService institutionRedisService) {
        this.cryptoService = cryptoService;
        this.institutionRedisService = institutionRedisService;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        String xEntityID = exchange.getIn().getHeader("X-Entity-ID", String.class);
        String xOperation = exchange.getIn().getHeader("x-operation", String.class);
        String payload = exchange.getIn().getBody(String.class);
        Institution institution = institutionRedisService.getInstitution(xEntityID);

        if (payload == null || payload.trim().isEmpty()) {
            throw new AbstractError("400", "Payload no puede ser vacío", "T");
        }

        if (xEntityID.isEmpty() || xOperation.isEmpty()) {
            throw new AbstractError("400", "Header x-operation no presente", "T");
        }
        logger.info("Procesando payload para institución: {}", institution.getId());

        // Firmar payload
        JWSResponse jwsResponse = cryptoService.signWithHeaders(payload, institution);

        // Encriptar payload firmado
        String encryptedPayload = cryptoService.encrypt(jwsResponse.getJwsCompact(), institution);
        JWEObject jweObject = JWEObject.parse(encryptedPayload);
        String xKey = (String) jweObject.getHeader().getCustomParam("x-key");
        String urlEnvio = "";

        WebClient webClient = exchange.getProperty("webClient", WebClient.class);
        if (webClient == null) {
            throw new IllegalStateException("WebClient con MTLS no disponible. Asegúrate de ejecutar MtlsProcessor primero.");
        }

        String operacion = xOperation.trim().toUpperCase();
        urlEnvio = institution.getEndpointUrl(operacion);

        if (urlEnvio == null) {
            throw new AbstractError("400", "EndPoint no Definido para operacion: " + operacion, "T");
        }

        try {
            HttpHeaders customHeaders = buildCustomHeaders(institution, jwsResponse, xKey);
            String jsonResponse = callExternalService(webClient, urlEnvio, encryptedPayload, customHeaders, institution.getTimeout());
            logger.info("Respuesta recibida: {}", jsonResponse);
            exchange.getMessage().setBody(jsonResponse);
        } catch (AbstractError e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new AbstractError("400", e.getMessage(), "T");
        } catch (IllegalStateException e) {
            throw new AbstractError("500", e.getMessage(), "T");
        } catch (Exception e) {
            String causeMessage = (e.getCause() != null) ? e.getCause().getMessage() : "Sin causa específica";
            throw new AbstractError("500", "Error interno: " + e.getMessage() + " - " + causeMessage, "T");
        }
    }


    private HttpHeaders buildCustomHeaders(Institution institution, JWSResponse jwsResponse, String xKey) {
        HttpHeaders customHeaders = new HttpHeaders();
        customHeaders.add("X-Entity-ID", institution.getId());
        customHeaders.add("Signature", jwsResponse.getSignatureHeader());
        customHeaders.add("Signature-Input", jwsResponse.getSignatureInput());
        customHeaders.add("digest", jwsResponse.getDigestHeader());
        customHeaders.add("x-key", xKey);

        return customHeaders;
    }

    private String callExternalService(WebClient webClient, String urlEnvio, String encryptedPayload,
                                       HttpHeaders customHeaders, int timeoutSeconds) {

        try {
            return webClient
                    .post()
                    .uri(urlEnvio)
                    .headers(httpHeaders -> httpHeaders.addAll(customHeaders))
                    .bodyValue(encryptedPayload)
                    .acceptCharset(StandardCharsets.UTF_8)
                    .retrieve()
                    .onStatus(
                            httpStatus -> httpStatus.is4xxClientError() || httpStatus.is5xxServerError(),
                            response -> response.bodyToMono(String.class)
                                    .map(errorBody -> new AbstractError(
                                            String.valueOf(response.statusCode().value()),
                                            "Error del servicio: " + errorBody,
                                            "T"
                                    ))
                    )
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .onErrorMap(TimeoutException.class, ex -> {
                        logger.error("Timeout detectado: {}", ex.getMessage());
                        return new AbstractError(HttpStatus.REQUEST_TIMEOUT.value(),
                                CodeResponse.TIMEOUTFB.getValue(),
                                "Timeout al conectar con el servicio externo", "T");
                    })
                    .onErrorMap(WebClientRequestException.class, ex -> {
                        logger.error("Error de conectividad detectado: {}", ex.getMessage());
                        return mapWebClientRequestException(ex, urlEnvio);
                    })
                    .doOnError(AbstractError.class, ex ->
                            logger.error("AbstractError propagándose correctamente: {}", ex.getMessage())
                    )
                    .blockOptional(Duration.ofSeconds(5L + timeoutSeconds))
                    .orElseThrow(() -> new AbstractError("500", "Respuesta vacía del servicio externo", "T"));

        } catch (AbstractError e) {
            throw e;
        } catch (Exception e) {
            throw new AbstractError(e, "T");
        }
    }
}

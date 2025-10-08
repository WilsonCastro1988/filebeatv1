package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.domain.jw.dto.JWSResponse;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
public class RawApiProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(RawApiProcessor.class);

    private final CryptoService cryptoService;
    private final WebClient webClient;
    private final IInstitutionRedisService institutionRedisService;

    public RawApiProcessor(CryptoService cryptoService, WebClient.Builder webClientBuilder, IInstitutionRedisService institutionRedisService) {
        this.cryptoService = cryptoService;
        this.webClient = webClientBuilder.build();
        this.institutionRedisService = institutionRedisService;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        String payload = exchange.getIn().getBody(String.class);
        Map<String, Object> headers = exchange.getIn().getHeaders();

        // 1️⃣ Extraer RECEIVER
        String receiver = (String) headers.get("xEntityID");
        if (receiver == null || receiver.isEmpty()) {
            throw new IllegalArgumentException("Header 'xEntityID' obligatorio");
        }

        // 2️⃣ Obtener institución desde Redis
        Institution institution = institutionRedisService.getInstitution(receiver);
        if (institution == null) {
            throw new IllegalArgumentException("Institución no encontrada para RECEIVER: " + receiver);
        }

        logger.info("Procesando payload para institución: {}", institution.getId());

        // 3️⃣ Firmar payload
        JWSResponse jwsResponse = cryptoService.signWithHeaders(payload, institution);

        // 4️⃣ Encriptar payload firmado
        String encryptedPayload = cryptoService.encrypt(jwsResponse.getJwsCompact(), institution);

        // 5️⃣ Preparar headers HTTP
        WebClient webClient = exchange.getProperty("webClient", WebClient.class);
        if (webClient == null) {
            throw new IllegalStateException("WebClient con MTLS no disponible. Asegúrate de ejecutar MtlsProcessor primero.");
        }

        // 6️⃣ Preparar headers HTTP
        WebClient.RequestBodySpec requestSpec = webClient.post()
                .uri(institution.getEndpoint()) // endpoint dinámico desde Redis
                .header("X-Entity-ID", institution.getId())
                .header("Signature", jwsResponse.getSignatureHeader())
                .header("Signature-Input", jwsResponse.getSignatureInput())
                .header("Digest", jwsResponse.getDigestHeader());

        headers.forEach((k, v) -> {
            if (!k.equalsIgnoreCase("xEntityID")) {
                requestSpec.header(k, v.toString());
            }
        });

        // 7️⃣ Enviar al endpoint externo y recibir respuesta
        Mono<String> responseMono = requestSpec.bodyValue(encryptedPayload)
                .retrieve()
                .bodyToMono(String.class);

        String externalResponse = responseMono.block();

        logger.info("Respuesta recibida del endpoint externo: {}", externalResponse);

        // 8️⃣ Devolver la respuesta al flujo Camel
        exchange.getMessage().setBody(externalResponse);
    }
}

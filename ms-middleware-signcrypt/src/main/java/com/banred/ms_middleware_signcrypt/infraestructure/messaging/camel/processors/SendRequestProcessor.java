package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Component
public class SendRequestProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(SendRequestProcessor.class);

    @Override
    public void process(Exchange exchange) throws Exception {

    }



    /*
    @Autowired
    private WebClient webClient; // Usar el bean configurado en WebClientConfig

    @Override
    public void process(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);
        if (institution == null) {
            throw new IllegalStateException("Institución no encontrada");
        }

        logger.info("🔐 Enviando petición al cliente externo para institución {}", institution.getId());

        // Obtener el cuerpo y cabeceras del Exchange
        String requestBody = exchange.getMessage().getBody(String.class);
        String xEntityID = exchange.getIn().getHeader("x-Entity-ID", String.class);
        String xKey = exchange.getIn().getHeader("x-key", String.class);
        String signatureInput = exchange.getIn().getHeader("Signature-Input", String.class);
        String digest = exchange.getIn().getHeader("digest", String.class);
        String signature = exchange.getIn().getHeader("Signature", String.class);

        Mono<String> responseMono = webClient.post()
                .uri(institution.getEndpoint())
                .header("x-Entity-ID", xEntityID)
                .header("x-key", xKey)
                .header("Signature-Input", signatureInput)
                .header("digest", digest)
                .header("Signature", signature)
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(30))
                .onErrorResume(e -> {
                    logger.error("❌ Error en el envío al cliente externo: {}", e.getMessage(), e);
                    return Mono.just("Error: " + e.getMessage());
                });

        String externalResponse = responseMono.block();
        logger.info("📥 Respuesta recibida del cliente externo: {}", externalResponse);

        exchange.getMessage().setBody(externalResponse);
        exchange.setProperty("externalResponse", externalResponse);
    }

     */
}

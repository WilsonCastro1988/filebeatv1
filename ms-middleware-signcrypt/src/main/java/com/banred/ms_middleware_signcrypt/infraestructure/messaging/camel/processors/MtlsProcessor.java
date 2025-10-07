package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;


import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.mtls.service.WebClientService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;

@Component
public class MtlsProcessor implements Processor {


    private static final Logger logger = LoggerFactory.getLogger(MtlsProcessor.class);

    private final WebClientService webClientService;

    public MtlsProcessor(WebClientService webClientService) {
        this.webClientService = webClientService;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        Institution institution = exchange.getProperty("institution", Institution.class);

        if (institution.getMtls() != null && institution.getMtls().isEnable()) {
            logger.info("🔐 Ejecutando llamada MTLS para institución {}", institution.getId());

            WebClient webClient = webClientService.createWebClient(institution);

            String responseBody = webClient.get()
                    .uri(institution.getEndpoint())
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(Duration.ofMillis(institution.getTimeout()));

            logger.info("📥 Respuesta MTLS: {}", responseBody);

            exchange.setProperty("mtlsResponse", responseBody);
            exchange.getMessage().setBody(responseBody);
        } else {
            logger.warn("⚠️ MTLS no habilitado para institución {}", institution.getId());
        }
    }

}

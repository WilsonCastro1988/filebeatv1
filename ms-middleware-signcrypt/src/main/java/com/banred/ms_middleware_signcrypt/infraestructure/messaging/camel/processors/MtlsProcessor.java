package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.mtls.service.WebClientService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

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
            logger.info("🔐 Verificando conexión MTLS para institución {}", institution.getId());

            // Crear WebClient con MTLS y realizar una verificación básica (e.g., HEAD o ping)
            WebClient webClient = webClientService.createWebClient(institution);
            Mono<String> healthCheck = webClient.get()
                    .uri(institution.getEndpoint()) // + "/health" Endpoint de verificación, ajusta según el cliente
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofMillis(institution.getTimeout()))
                    .onErrorResume(e -> {
                        logger.error("❌ Fallo en la verificación MTLS: {}", e.getMessage(), e);
                        return Mono.error(new RuntimeException("Fallo en la verificación MTLS", e));
                    });

            String response = healthCheck.block(); // Bloquea para simular verificación
            logger.info("✅ Conexión MTLS verificada para institución {}", institution.getId());
            exchange.setProperty("webClient", webClient); // Guardar WebClient para uso posterior
        } else {
            logger.warn("⚠️ MTLS no habilitado para institución {}", institution.getId());
        }
    }
}

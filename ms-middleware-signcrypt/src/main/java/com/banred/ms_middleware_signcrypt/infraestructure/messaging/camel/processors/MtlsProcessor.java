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
    public void process(Exchange exchange) {
        Institution institution = exchange.getProperty("institution", Institution.class);

        if (institution.getMtls() != null && institution.getMtls().isEnable()) {
            logger.info("🔐 Configurando WebClient MTLS para institución {}", institution.getId());

            WebClient webClient = webClientService.createWebClient(institution);

            // Guardar WebClient para su uso posterior
            exchange.setProperty("webClient", webClient);

            logger.info("✅ WebClient MTLS listo para institución {}", institution.getId());

            // Opcional: si quieres verificar, podrías hacer health check async sin bloquear:
            webClient.get()
                    .uri(institution.getEndpoint()) // Ajusta a /health si lo deseas
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofMillis(institution.getTimeout()))
                    .doOnError(e -> logger.warn("⚠️ Health check MTLS fallido para {}: {}", institution.getId(), e.getMessage()))
                    .subscribe(); // No bloquea, solo registra errores
        } else {
            logger.warn("⚠️ MTLS no habilitado para institución {}", institution.getId());
        }
    }
}

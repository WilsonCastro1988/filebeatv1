package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.RawApiInProcessor;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class MiddlewareInRoute extends RouteBuilder {

    private final RawApiInProcessor rawApiResponseProcessor;
    private final IInstitutionRedisService institutionRedisService;


    public MiddlewareInRoute(RawApiInProcessor rawApiResponseProcessor, IInstitutionRedisService institutionRedisService) {
        this.rawApiResponseProcessor = rawApiResponseProcessor;
        this.institutionRedisService = institutionRedisService;
    }

    @Override
    public void configure() {
        from("direct:raw-api-in")
                .routeId("raw-api-in")
                .log("🔐 Procesando respuesta raw-api: ${body}")
                .process(exchange -> {
                    // Recuperar institución y setearla en Exchange
                    String xEntityID = exchange.getIn().getHeader("xEntityID", String.class);
                    if (xEntityID == null || xEntityID.isEmpty()) {
                        throw new IllegalArgumentException("Header xEntityID no presente");
                    }
                    Institution institution = institutionRedisService.getInstitution(xEntityID);
                    if (institution == null) {
                        throw new IllegalStateException("No se encontró institución para RECEIVER: " + xEntityID);
                    }
                    exchange.setProperty("institution", institution);
                })
                .process(rawApiResponseProcessor)
                .log("✅ Payload limpio listo para devolver: ${body}");
    }
}

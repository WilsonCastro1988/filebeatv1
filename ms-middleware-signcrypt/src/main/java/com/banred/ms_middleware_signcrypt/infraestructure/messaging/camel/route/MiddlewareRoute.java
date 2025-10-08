package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.domain.jw.dto.JWSResponse;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.*;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class MiddlewareRoute extends RouteBuilder {


    private final RawApiProcessor rawApiProcessor;
    private final MtlsProcessor mtlsRequestProcessor;
    private final InstitutionLookupProcessor institutionLookupProcessor;
    private final IInstitutionRedisService institutionRedisService;


    public MiddlewareRoute(RawApiProcessor rawApiProcessor, MtlsProcessor mtlsRequestProcessor, InstitutionLookupProcessor institutionLookupProcessor, IInstitutionRedisService institutionRedisService) {
        this.rawApiProcessor = rawApiProcessor;
        this.mtlsRequestProcessor = mtlsRequestProcessor;
        this.institutionLookupProcessor = institutionLookupProcessor;
        this.institutionRedisService = institutionRedisService;
    }


    @Override
    public void configure() {
        from("direct:raw-api")
                .routeId("raw-api")
                .log("🔐 Iniciando procesamiento raw-api para payload: ${body}")
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
                .choice()
                .when(simple("${exchangeProperty.institution.mtls.enable} == true"))
                .process(mtlsRequestProcessor)
                .end()
                .process(rawApiProcessor) // Firma, encripta y envía dinámicamente
                .log("✅ Respuesta devuelta por raw-api: ${body}");
    }
}

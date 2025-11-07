package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.*;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class OperationRoute extends RouteBuilder {

    private final InstitutionLookupProcessor institutionLookupProcessor;

    public OperationRoute(InstitutionLookupProcessor institutionLookupProcessor) {
        this.institutionLookupProcessor = institutionLookupProcessor;
    }

    @Override
    public void configure() {
        from("direct:operation")
                .routeId("operation_route")
                .log("🔐 Iniciando procesamiento para institución: ${body}")
                .process(institutionLookupProcessor)
                .choice()
                .when(simple("${exchangeProperty.payload.direction} == 'IN'"))
                .to("direct:operation_in_flow")
                .when(simple("${exchangeProperty.payload.direction} == 'OUT'"))
                .to("direct:operation_out_flow")
                .otherwise()
                .throwException(new IllegalArgumentException("Dirección inválida: se espera IN u OUT"))
                .end();
    }
}

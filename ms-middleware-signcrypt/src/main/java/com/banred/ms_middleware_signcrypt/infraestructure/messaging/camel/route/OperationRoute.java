package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.*;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class OperationRoute extends RouteBuilder {

    @Autowired
    private InstitutionLookupProcessor institutionLookupProcessor;
    @Autowired
    private MtlsProcessor mtlsRequestProcessor;
    @Autowired
    private ResponseProcessor responseProcessor;

    @Autowired
    private JweDecryptProcessor jweDecryptProcessor;
    @Autowired
    private JwsVerifySignProcessor jwsVerifyProcessor;


    @Autowired
    private JwsProcessor jwsProcessor;
    @Autowired
    private JweProcessor jweProcessor;


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

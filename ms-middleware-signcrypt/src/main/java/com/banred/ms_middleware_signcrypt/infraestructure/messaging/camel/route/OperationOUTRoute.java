package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JweProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JwsProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.MtlsProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.ResponseProcessor;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class OperationOUTRoute extends RouteBuilder {


    @Autowired
    private MtlsProcessor mtlsRequestProcessor;
    @Autowired
    private ResponseProcessor responseProcessor;


    @Autowired
    private JwsProcessor jwsProcessor;
    @Autowired
    private JweProcessor jweProcessor;


    @Override
    public void configure() {
       from("direct:operation_out_flow")
                .routeId("operation_out_flow")
                .log("➡️ Dirección OUT detectada")
                .choice()
                .when(simple("${exchangeProperty.institution.mtls.enable} == true"))
                .process(mtlsRequestProcessor)
                .end()
                .choice()
                .when(simple("${exchangeProperty.institution.jws.enable} == true"))
                .process(jwsProcessor) // firma
                .end()
                .choice()
                .when(simple("${exchangeProperty.institution.jwe.enable} == true"))
                .process(jweProcessor) // encriptar mensaje
                .end()
                .process(responseProcessor)
                .log("✅ Procesamiento OUT completo: ${body}");
    }
}

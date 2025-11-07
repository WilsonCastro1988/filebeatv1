package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JweProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JwsProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.ResponseProcessor;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class OperationOUTRoute extends RouteBuilder {

    private final ResponseProcessor responseProcessor;
    private final JwsProcessor jwsProcessor;
    private final JweProcessor jweProcessor;

    public OperationOUTRoute(ResponseProcessor responseProcessor,
                             JwsProcessor jwsProcessor, JweProcessor jweProcessor) {
        this.responseProcessor = responseProcessor;
        this.jwsProcessor = jwsProcessor;
        this.jweProcessor = jweProcessor;
    }


    @Override
    public void configure() {
        from("direct:operation_out_flow")
                .routeId("operation_out_flow")
                .log("➡️ Dirección OUT detectada")
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

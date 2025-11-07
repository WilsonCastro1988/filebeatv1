package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JweDecryptProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JwsVerifySignProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.ResponseProcessor;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class OperationINRoute extends RouteBuilder {


    private final ResponseProcessor responseProcessor;
    private final JweDecryptProcessor jweDecryptProcessor;
    private final JwsVerifySignProcessor jwsVerifyProcessor;


    public OperationINRoute(ResponseProcessor responseProcessor,
                            JweDecryptProcessor jweDecryptProcessor,
                            JwsVerifySignProcessor jwsVerifyProcessor) {
        this.responseProcessor = responseProcessor;
        this.jweDecryptProcessor = jweDecryptProcessor;
        this.jwsVerifyProcessor = jwsVerifyProcessor;
    }


    @Override
    public void configure() {
        from("direct:operation_in_flow")
                .routeId("operation_in_flow")
                .log("➡️ Dirección IN detectada")
                .choice()
                .when(simple("${exchangeProperty.institution.jwe.enable} == true"))
                .process(jweDecryptProcessor) // Desencriptar JWE primero
                .end()
                .choice()
                .when(simple("${exchangeProperty.institution.jws.enable} == true"))
                .process(jwsVerifyProcessor) // Verificar JWS después
                .end()
                .process(responseProcessor)
                .log("✅ Procesamiento IN completo: ${body}");
    }
}

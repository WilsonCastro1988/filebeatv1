package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JweDecryptProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.JwsVerifySignProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.MtlsProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.ResponseProcessor;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class OperationINRoute extends RouteBuilder {


    @Autowired
    private MtlsProcessor mtlsRequestProcessor;
    @Autowired
    private ResponseProcessor responseProcessor;

    @Autowired
    private JweDecryptProcessor jweDecryptProcessor;
    @Autowired
    private JwsVerifySignProcessor jwsVerifyProcessor;


    @Override
    public void configure() {
        from("direct:operation_in_flow")
                .routeId("operation_in_flow")
                .log("➡️ Dirección IN detectada")
                .choice()
                .when(simple("${exchangeProperty.institution.mtls.enable} == true"))
                .process(mtlsRequestProcessor)
                .end()
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

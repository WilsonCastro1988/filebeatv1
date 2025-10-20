package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.route;

import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.MiddlerwareLookupProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.MtlsProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.RawApiInProcessor;
import com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors.RawApiOutProcessor;
import org.apache.camel.builder.RouteBuilder;
import org.springframework.stereotype.Component;

@Component
public class MiddlewareRoute extends RouteBuilder {


    private final RawApiOutProcessor rawApiOutProcessor;
    private final RawApiInProcessor rawApiInProcessor;
    private final MtlsProcessor mtlsRequestProcessor;
    private final MiddlerwareLookupProcessor middlerwareLookupProcessor;


    public MiddlewareRoute(RawApiOutProcessor rawApiProcessor, RawApiInProcessor rawApiInProcessor, MtlsProcessor mtlsRequestProcessor, MiddlerwareLookupProcessor middlerwareLookupProcessor) {
        this.rawApiOutProcessor = rawApiProcessor;
        this.rawApiInProcessor = rawApiInProcessor;
        this.mtlsRequestProcessor = mtlsRequestProcessor;
        this.middlerwareLookupProcessor = middlerwareLookupProcessor;
    }


    @Override
    public void configure() {
        from("direct:middleware")
                .routeId("middleware")
                .log("🔐 Iniciando procesamiento middleware para payload: ${body}")
                .process(middlerwareLookupProcessor)
                .choice()
                .when(simple("${exchangeProperty.middleware} == 'out'"))
                .process(mtlsRequestProcessor)
                .end()
                .choice()
                .when(simple("${exchangeProperty.middleware} == 'out'"))
                .process(rawApiOutProcessor) // Firma, encripta y envía dinámicamente
                .end()
                .choice()
                .when(simple("${exchangeProperty.middleware} == 'in'"))
                .process(rawApiInProcessor) // Desencripta, valida firma
                .end()
                .log("✅ Respuesta devuelta por middleware: ${body}");
    }
}

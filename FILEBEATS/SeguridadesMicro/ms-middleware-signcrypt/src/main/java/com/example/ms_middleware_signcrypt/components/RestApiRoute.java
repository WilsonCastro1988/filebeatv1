package com.example.ms_middleware_signcrypt.components;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.rest.RestBindingMode;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class RestApiRoute extends RouteBuilder {

    @Override
    public void configure() throws Exception {
        // Configurar el componente REST
        restConfiguration()
                .component("servlet")
                .bindingMode(RestBindingMode.json)
                .dataFormatProperty("prettyPrint", "true")
                .contextPath("/api")
                .port(8080);

        // Definir el endpoint REST
        rest("/logs")
                .post()
                .consumes("application/json")
                .produces("application/json")
                .to("direct:processLog"); // Redirige a una ruta interna

        // Ruta interna para procesar el log
        from("direct:processLog")
                .routeId("rest-to-elasticsearch")
                .process(exchange -> {
                    Object body = exchange.getIn().getBody();
                    Map<String, Object> bodyMap;

                    // Verificar si el cuerpo es un Map<String, Object>
                    if (body instanceof Map<?, ?>) {
                        bodyMap = new HashMap<>();
                        for (Map.Entry<?, ?> entry : ((Map<?, ?>) body).entrySet()) {
                            if (entry.getKey() instanceof String) {
                                bodyMap.put((String) entry.getKey(), entry.getValue());
                            }
                        }
                        // Agregar campos personalizados
                        bodyMap.put("processed_by", "camel-rest");
                        bodyMap.put("@timestamp", new java.util.Date().toString());
                    } else {
                        // Si no es un Map, crear uno nuevo con un mensaje de error
                        bodyMap = new HashMap<>();
                        bodyMap.put("error", "El cuerpo de la solicitud no es un JSON válido");
                        bodyMap.put("@timestamp", new java.util.Date().toString());
                        exchange.getIn().setHeader("CamelHttpResponseCode", 400);
                    }

                    exchange.getIn().setBody(bodyMap);
                })
                .to("elasticsearch://local?operation=Index&indexName=springboot-logs-rest-4.8.0-%{+yyyy.MM.dd}")
                .setBody(simple("{\"message\": \"Log procesado y enviado a Elasticsearch\"}"));
    }
}

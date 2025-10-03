package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.jw.service.CryptoService;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.springframework.stereotype.Component;

@Component
public class JwsProcessor implements Processor {

    private final CryptoService cryptoService;

    public JwsProcessor(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        try {
            Institution institution = exchange.getProperty("institution", Institution.class);
            String body = exchange.getIn().getBody(String.class);

            // Aquí puedes definir si firmas o verificas
            String signed = cryptoService.encryptData(body);
            String verified = cryptoService.decrypt(signed, institution);

            exchange.getIn().setBody(verified);
        }catch (Exception e) {
            exchange.setException(e);
        }

    }
}

package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.common.constant.StatusResponse;
import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMResponseDTO;
import com.banred.ms_middleware_signcrypt.domain.apim.dto.SignatureDTO;
import com.nimbusds.jose.shaded.gson.Gson;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Date;

import static com.banred.ms_middleware_signcrypt.common.util.Utilities.getDateStringISO8601;

@Component
public class ResponseProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(ResponseProcessor.class);


    @Override
    public void process(Exchange exchange) throws ParseException {

        String responseBody = exchange.getMessage().getBody(String.class);
        String xEntityID = exchange.getIn().getHeader("xEntityID").toString();
        String xkey = exchange.getIn().getHeader("x-key").toString();
        String toIN = exchange.getIn().getHeader("timestamp_in").toString();
        String ssInput = exchange.getProperty("sign.Signature-Input", String.class);
        String ssDigest = exchange.getProperty("sign.digest", String.class);
        String ssSignature = exchange.getProperty("sign.Signature", String.class);

        SignatureDTO signatureDTO = new SignatureDTO();
        signatureDTO.setDigest(ssDigest);
        signatureDTO.setSignature(ssSignature);
        signatureDTO.setSignatureInput(ssInput);

        APIMResponseDTO dto = new APIMResponseDTO();
        dto.setxEntityID(xEntityID);
        dto.setxKey(xkey);
        dto.setPayload(responseBody);
        dto.setStatus(StatusResponse.SUCCESS.getValue());
        dto.setTimestamp_OUT(getDateStringISO8601(new Date()));
        dto.setTimestamp_IN(toIN);
        dto.setSign(signatureDTO);

        Gson gson = new Gson();
        exchange.getMessage().setBody(gson.toJson(dto));
    }
}

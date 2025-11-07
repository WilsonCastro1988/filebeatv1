package com.banred.ms_middleware_signcrypt.infraestructure.messaging.camel.processors;

import com.banred.ms_middleware_signcrypt.common.constant.StatusResponse;
import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMResponseDTO;
import com.banred.ms_middleware_signcrypt.domain.apim.dto.SignatureDTO;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

import static com.banred.ms_middleware_signcrypt.common.util.Utilities.getDateStringISO8601;

@Component
public class ResponseProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(ResponseProcessor.class);

    @Override
    public void process(Exchange exchange) throws ParseException {
        try {
            String payloadBase64 = "";
            String responseBody = exchange.getMessage().getBody(String.class);
            String xEntityID = exchange.getIn().getHeader("X-Entity-ID", String.class);
            String xKey = exchange.getIn().getHeader("x-key", String.class);
            String timestampIn = exchange.getIn().getHeader("timestamp_in", String.class);
            String signatureInput = exchange.getIn().getHeader("Signature-Input", String.class);
            String digest = exchange.getIn().getHeader("digest", String.class);
            String signature = exchange.getIn().getHeader("Signature", String.class);

            if (exchange.getProperty("payload", APIMRequestDTO.class).getDirection().equals("IN")) {
                JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();
                String xml = jsonObject.get("data").getAsString();
                payloadBase64 = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
            } else {
                payloadBase64 = responseBody;
            }
            SignatureDTO signatureDTO = new SignatureDTO();
            signatureDTO.setDigest(digest);
            signatureDTO.setSignature(signature);
            signatureDTO.setSignatureInput(signatureInput);

            APIMResponseDTO dto = new APIMResponseDTO();
            dto.setXEntityID(xEntityID);
            dto.setXKey(xKey);
            dto.setPayload(payloadBase64);
            dto.setStatus(StatusResponse.SUCCESS.getValue());
            dto.setTimestampOut(getDateStringISO8601(new Date()));
            dto.setTimestampIn(timestampIn);
            dto.setSign(signatureDTO);

            Gson gson = new Gson();
            String requestBody = gson.toJson(dto);
            logger.debug("Respuesta preparada: {}", requestBody);

            exchange.getMessage().setBody(requestBody);

        } catch (AbstractException e) {
            logger.error("Error al construir la respuesta: {}", e.getMessage(), e);
            APIMResponseDTO errorDto = new APIMResponseDTO();
            errorDto.setStatus(StatusResponse.ERROR.getValue());
            errorDto.setTimestampOut(getDateStringISO8601(new Date()));
            errorDto.setPayload("Error al construir la respuesta: " + e.getMessage());
            exchange.getMessage().setBody(new Gson().toJson(errorDto));
        }
    }
}

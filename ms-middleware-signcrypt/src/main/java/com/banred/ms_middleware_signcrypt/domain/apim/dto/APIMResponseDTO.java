package com.banred.ms_middleware_signcrypt.domain.apim.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.io.Serializable;

@Data
public class APIMResponseDTO implements Serializable {

    private String xEntityID;
    private String xKey;
    private String payload;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private SignatureDTO sign;
    private String timestamp_IN;
    private String timestamp_OUT;
    private String status;


    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getTimestamp_IN() {
        return timestamp_IN;
    }

    public void setTimestamp_IN(String timestamp_IN) {
        this.timestamp_IN = timestamp_IN;
    }

    public String getTimestamp_OUT() {
        return timestamp_OUT;
    }

    public void setTimestamp_OUT(String timestamp_OUT) {
        this.timestamp_OUT = timestamp_OUT;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getxEntityID() {
        return xEntityID;
    }

    public void setxEntityID(String xEntityID) {
        this.xEntityID = xEntityID;
    }

    public String getxKey() {
        return xKey;
    }

    public void setxKey(String xKey) {
        this.xKey = xKey;
    }

    public SignatureDTO getSign() {
        return sign;
    }

    public void setSign(SignatureDTO sign) {
        this.sign = sign;
    }
}

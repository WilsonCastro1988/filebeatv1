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
    private String timestampIn;
    private String timestampOut;
    private String status;

}

package com.banred.ms_middleware_signcrypt.model;

import lombok.Data;

@Data
public class APIMResponseDTO {
    private String xEntityID;
    private String xKey;
    private String payload;
    private SignatureDTO sign;
    private String timestamp_IN;
    private String timestamp_OUT;
    private String status;
}

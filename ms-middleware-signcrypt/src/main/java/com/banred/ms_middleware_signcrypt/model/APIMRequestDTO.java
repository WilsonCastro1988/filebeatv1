package com.banred.ms_middleware_signcrypt.model;

import lombok.Data;

@Data
public class APIMRequestDTO {
    private String xEntityID;
    private String direction;
    private String data;
    private String xKey;
    private SignatureDTO sign;
}

package com.banred.ms_middleware_signcrypt.domain.apim.dto;

import lombok.Data;

@Data
public class SignatureDTO {
    private String signatureInput;
    private String digest;
    private String signature;
}

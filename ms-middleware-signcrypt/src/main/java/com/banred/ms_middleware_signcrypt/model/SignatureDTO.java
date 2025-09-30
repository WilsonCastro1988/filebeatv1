package com.banred.ms_middleware_signcrypt.model;

import lombok.Data;

@Data
public class SignatureDTO {
    private String signatureInput;
    private String digest;
    private String signature;
}

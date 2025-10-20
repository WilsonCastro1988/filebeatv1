package com.banred.ms_middleware_signcrypt.domain.apim.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.io.Serializable;


@Data
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class SignatureDTO implements Serializable {

    @Size(max = 1024, message = "Longitud no puede tener más de 1024 caracteres")
    private String signatureInput;

    @Size(max = 1024, message = "Longitud no puede tener más de 1024 caracteres")
    private String digest;

    @Size(max = 4096, message = "Longitud no puede tener más de 4096 caracteres")
    private String signature;

}

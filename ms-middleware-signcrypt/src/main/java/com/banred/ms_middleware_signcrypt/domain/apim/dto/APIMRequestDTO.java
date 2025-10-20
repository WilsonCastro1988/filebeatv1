package com.banred.ms_middleware_signcrypt.domain.apim.dto;

import com.banred.ms_middleware_signcrypt.infraestructure.validators.ValidConditionalSignature;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Data
@Getter
@Setter
@ValidConditionalSignature
public class APIMRequestDTO implements Serializable {


    @NotBlank(message = "Campo es requerido")
    @Size(max = 10, message = "Longitud no puede tener más de 10 caracteres")
    @Pattern(regexp = "^\\d{4,10}$", message = "Campo debe contener mínimo 4 caracteres")
    private String xEntityID;

    @NotBlank(message = "Campo es requerido")
    @Pattern(regexp = "^(IN|OUT)$", message = "Campo solo puede ser IN o OUT")
    private String direction;

    @NotBlank(message = "Campo es requerido")
    private String data;

    @NotBlank(message = "Campo es requerido")
    @Size(max = 4096, message = "Longitud no puede ser más de 4096 caracteres")
    private String xKey;

    @Valid
    private SignatureDTO sign;

}

package com.banred.ms_middleware_signcrypt.infraestructure.validators;

import com.banred.ms_middleware_signcrypt.domain.apim.dto.APIMRequestDTO;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ConditionalSignatureValidator implements ConstraintValidator<ValidConditionalSignature, APIMRequestDTO> {


    private static final String ERROR_MESSAGE = "El campo es obligatorio cuando 'direction' es IN";
    private static final String ADMIT_DIRECTION_VALUE = "IN";

    @Override
    public boolean isValid(APIMRequestDTO dto, ConstraintValidatorContext context) {
        if (dto == null) return true;

        boolean isValid = true;

        if (ADMIT_DIRECTION_VALUE.equalsIgnoreCase(dto.getDirection())) {
            context.disableDefaultConstraintViolation();

            if (dto.getSign() == null || dto.getSign().getSignatureInput() == null || dto.getSign().getSignatureInput().isEmpty()) {
                context.buildConstraintViolationWithTemplate(ERROR_MESSAGE)
                        .addPropertyNode("sign.signatureInput")
                        .addConstraintViolation();
                isValid = false;
            }

            if (dto.getSign() == null || dto.getSign().getDigest() == null || dto.getSign().getDigest().isEmpty()) {
                context.buildConstraintViolationWithTemplate(ERROR_MESSAGE)
                        .addPropertyNode("sign.digest")

                        .addConstraintViolation();
                isValid = false;
            }

            if (dto.getSign() == null || dto.getSign().getSignature() == null || dto.getSign().getSignature().isEmpty()) {
                context.buildConstraintViolationWithTemplate(ERROR_MESSAGE)
                        .addPropertyNode("sign.signature")
                        .addConstraintViolation();
                isValid = false;
            }
        }

        return isValid;
    }
}
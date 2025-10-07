package com.banred.ms_middleware_signcrypt.infraestructure.validators;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = ConditionalSignatureValidator.class)
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidConditionalSignature {
    String message() default "El campo es requerido cuando 'direction' es IN";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}

package com.banred.ms_middleware_signcrypt.common.exception.handler;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.common.exception.payloads.ErrorResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {


    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDto> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ErrorResponseDto response = new ErrorResponseDto("FAILED", "INVALID_REQUEST", errors);

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }


    @ExceptionHandler(AbstractException.class)
    public ResponseEntity<Map<String, Object>> handleAbstractException(AbstractException ex) {
        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("status", ex.getCodigoHttp());
        errorBody.put("error", ex.getMessage());
        errorBody.put("error_description", ex.getTipo());
        return ResponseEntity.status(ex.getCodigoHttp()).body(errorBody);
    }

}


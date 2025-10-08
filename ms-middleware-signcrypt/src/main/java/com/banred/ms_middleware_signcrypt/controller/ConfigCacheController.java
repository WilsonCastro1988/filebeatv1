package com.banred.ms_middleware_signcrypt.controller;

import com.banred.ms_middleware_signcrypt.domain.event.dto.EventoInterno;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
@CrossOrigin(origins = "*")
public class ConfigCacheController {

    private final ApplicationEventPublisher applicationEventPublisher;

    public ConfigCacheController(ApplicationEventPublisher applicationEventPublisher){
        this.applicationEventPublisher = applicationEventPublisher;
    }
    
    @PostMapping("rechargecacheinformation")
    public ResponseEntity<String> rechargecacheinformation(@RequestBody EventoInterno entity) {

        try {
            this.applicationEventPublisher.publishEvent(new EventoInterno(entity.getTipo(), entity.getTimestamp()));
            return ResponseEntity.ok("Evento publicado con exito");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error al publicar evento");
        }
        
    }
    
}

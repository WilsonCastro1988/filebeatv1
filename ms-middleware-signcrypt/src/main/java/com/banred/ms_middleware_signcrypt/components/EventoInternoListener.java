package com.banred.ms_middleware_signcrypt.components;


import com.banred.ms_middleware_signcrypt.model.EventoInterno;
import com.banred.ms_middleware_signcrypt.service.IInstitutionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class EventoInternoListener {
    
    @Autowired
    private IInstitutionService institutionService;


    @EventListener
    public void manejarEventoInterno(EventoInterno evento) {
        try{
            institutionService.loadInstitutions();
        }catch(Exception e){
            throw new RuntimeException("Error al actualizar redis " + e.getMessage());
        }
    }
}

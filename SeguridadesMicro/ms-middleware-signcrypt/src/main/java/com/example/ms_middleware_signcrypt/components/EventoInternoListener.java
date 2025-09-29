package com.example.ms_middleware_signcrypt.components;


import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import com.example.ms_middleware_signcrypt.model.EventoInterno;

@Component
public class EventoInternoListener {
    
    @EventListener
    public void manejarEventoInterno(EventoInterno evento) {
        try{
            //System.out.println("Evento capturado, actualizar redis");
        }catch(Exception e){
            //System.out.println("Error Evento capturado " + e.getMessage());
        }
    }
}

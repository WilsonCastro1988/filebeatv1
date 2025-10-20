package com.banred.ms_middleware_signcrypt.infraestructure.messaging.event;


import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.common.exception.AbstractException;
import com.banred.ms_middleware_signcrypt.domain.event.dto.EventoInterno;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class EventoInternoListener {

    private final IInstitutionService institutionService;


    public EventoInternoListener(IInstitutionService institutionService) {
        this.institutionService = institutionService;
    }


    @EventListener
    public void manejarEventoInterno(EventoInterno evento) {
        try {
            institutionService.loadInstitutions();
        } catch (AbstractException e) {
            throw new AbstractError(e, "Error al actualizar redis " + e.getMessage());
        }
    }
}

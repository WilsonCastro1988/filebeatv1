package com.banred.ms_middleware_signcrypt.domain.institution.service.impl;

import com.banred.ms_middleware_signcrypt.common.exception.AbstractError;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institutions;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionService;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class InstitutionServiceImpl implements IInstitutionService {


    private final IInstitutionRedisService institutionRedisService;

    @Value("${microservice.parameters.RUTA_CONFIG_XML}")
    private String rutaConfigXml;

    private Institutions institutions;

    public InstitutionServiceImpl(IInstitutionRedisService institutionRedisService) {
        this.institutionRedisService = institutionRedisService;
    }

    @Override
    public void loadInstitutions() {
        try {
            File file = new File(rutaConfigXml);
            JAXBContext jaxbContext = JAXBContext.newInstance(Institutions.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            institutions = (Institutions) unmarshaller.unmarshal(file);
            institutionRedisService.saveInstitutions(institutions);
        }catch (JAXBException e) {
            throw new AbstractError(e, "Error al leer config service ");
        }

    }
    @Override
    public Institutions getInstitutions() {
        return institutions;
    }

    @Override
    public Institution getInstitutionById(String id) {
        return null;
    }

}

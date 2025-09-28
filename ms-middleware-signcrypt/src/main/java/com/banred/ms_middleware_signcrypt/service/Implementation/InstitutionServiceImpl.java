package com.banred.ms_middleware_signcrypt.service.Implementation;

import com.banred.ms_middleware_signcrypt.model.Institution;
import com.banred.ms_middleware_signcrypt.model.Institutions;
import com.banred.ms_middleware_signcrypt.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.service.IInstitutionService;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class InstitutionServiceImpl implements IInstitutionService {

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    @Value("${microservice.parameters.RUTA_CONFIG_XML}")
    private String RUTA_CONFIG_XML;

    private Institutions institutions;

    @Override
    public void loadInstitutions() {
        try {
            File file = new File(RUTA_CONFIG_XML);
            JAXBContext jaxbContext = JAXBContext.newInstance(Institutions.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            institutions = (Institutions) unmarshaller.unmarshal(file);
            institutionRedisService.saveInstitutions(institutions);
        }catch (JAXBException e) {
            throw new RuntimeException("Error al leer config service " + e.getMessage());
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

package com.example.ms_middleware_signcrypt.service.Implementation;

import java.io.File;

import org.springframework.stereotype.Service;

import com.example.ms_middleware_signcrypt.model.Institution;
import com.example.ms_middleware_signcrypt.model.Institutions;
import com.example.ms_middleware_signcrypt.service.IInstitutionService;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;

@Service
public class InstitutionServiceImpl implements IInstitutionService {
    
    private Institutions institutions;

    @Override
    public void loadInstitutions() {
        try {

//            File file = new File("/c/Users/User/Desktop/SeguridadesMicro/config-service.xml"); // TODO: Cambiar path para que sea dinamico
            File file = new File("C:\\Users\\User\\Desktop\\SeguridadesMicro\\config-service.xml");
            JAXBContext jaxbContext = JAXBContext.newInstance(Institutions.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            institutions = (Institutions) unmarshaller.unmarshal(file);
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

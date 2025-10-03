package com.banred.ms_middleware_signcrypt.domain.institution.controller;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institution;
import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institutions;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionRedisService;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionService;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/xml")
@Slf4j
public class InstitutionController {
    
    @Autowired
    private IInstitutionService institutionService;

    @Autowired
    private IInstitutionRedisService institutionRedisService;

    @PostMapping("/getXml")
    public Institutions getXml() throws JsonProcessingException{
        institutionService.loadInstitutions();

        Institution institution;
        institution = institutionRedisService.getInstitution("0001");
        //log.info("Institutions loaded: {}", institution);
       
        return institutionService.getInstitutions();
    }
}

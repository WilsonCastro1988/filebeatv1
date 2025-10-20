package com.banred.ms_middleware_signcrypt.domain.institution.controller;

import com.banred.ms_middleware_signcrypt.domain.institution.model.dto.Institutions;
import com.banred.ms_middleware_signcrypt.domain.institution.service.IInstitutionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/xml")
@Slf4j
public class InstitutionController {

    private final IInstitutionService institutionService;

    public InstitutionController(IInstitutionService institutionService) {
        this.institutionService = institutionService;
    }

    @PostMapping("/getXml")
    public Institutions getXml() {
        institutionService.loadInstitutions();
        return institutionService.getInstitutions();
    }
}

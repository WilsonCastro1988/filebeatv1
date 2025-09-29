package com.example.ms_middleware_signcrypt.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.example.ms_middleware_signcrypt.model.Institutions;
import com.example.ms_middleware_signcrypt.service.IInstitutionService;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/xml")
public class InstitutionController {
    private static final Logger logger = LoggerFactory.getLogger(InstitutionController.class);    @GetMapping("/test")
    public String test() {
        logger.info("Log de prueba generado!");
        return "Log generado";
    }
    @Autowired
    private IInstitutionService institutionService;

    @PostMapping("/getXml")
    public Institutions getXml(){
        institutionService.loadInstitutions();
        return institutionService.getInstitutions();
    }
}

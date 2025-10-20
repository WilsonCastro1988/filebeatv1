package com.banred.ms_middleware_signcrypt.domain.institution.model.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@XmlRootElement(name = "Institutions")
@XmlAccessorType(XmlAccessType.FIELD)
@Getter
@Setter
public class Institutions {
    @XmlElement(name ="Institution")
    private List<Institution> institutionList;
}

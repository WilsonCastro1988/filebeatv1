package com.example.ms_middleware_signcrypt.model;

import java.util.List;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.Getter;
import lombok.Setter;

@XmlRootElement(name = "Institutions")
@XmlAccessorType(XmlAccessType.FIELD)
@Getter
@Setter
public class Institutions {
    @XmlElement(name ="Institution")
    private List<Institution> institutions;
}

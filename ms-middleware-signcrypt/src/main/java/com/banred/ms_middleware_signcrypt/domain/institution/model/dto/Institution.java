package com.banred.ms_middleware_signcrypt.domain.institution.model.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
@Setter
@XmlAccessorType(XmlAccessType.FIELD)
public class Institution {

    @XmlAttribute(name = "id")
    private String id;

    @XmlElement(name = "name")
    private String name;

    @XmlElement(name = "tls")
    private boolean tls;

    @XmlElement(name = "timeout")
    private int timeout;

    @XmlElementWrapper(name = "endpoints")
    @XmlElement(name = "endpoint")
    private List<Endpoint> endpoints;

    @XmlElement(name = "mtls")
    private SecurityConfig mtls;

    @XmlElement(name = "jws")
    private SecurityConfig jws;

    @XmlElement(name = "jwe")
    private SecurityConfig jwe;

    public String getEndpointUrl(String tipoOperacion) {
        if (endpoints == null) return null;
        Map<String, String> map = endpoints.stream()
                .collect(Collectors.toMap(Endpoint::getTipo, Endpoint::getUrl));
        return map.get(tipoOperacion);
    }
}

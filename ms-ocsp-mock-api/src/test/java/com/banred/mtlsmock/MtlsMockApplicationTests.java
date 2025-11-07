package com.banred.mtlsmock;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@AutoConfigureMockMvc
class MtlsMockApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    private String basicAuth(String username, String password) {
        String auth = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(auth.getBytes());
    }

    @Test
    void whenRequestHasCertificate_thenAuthenticateWithMtlsProvider() throws Exception {
        X509Certificate mockCert = Mockito.mock(X509Certificate.class);
        Mockito.when(mockCert.getSubjectX500Principal())
                .thenReturn(new X500Principal("CN=client, OU=test, O=org, C=EC"));

        PreAuthenticatedAuthenticationToken token =
                new PreAuthenticatedAuthenticationToken(
                        new User("client", "", List.of(new SimpleGrantedAuthority("ROLE_USER"))),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                );
        SecurityContextHolder.getContext().setAuthentication(token);


        mockMvc.perform(get("/api/secure/mtls")
                        .requestAttr("javax.servlet.request.X509Certificate", new X509Certificate[]{mockCert}))
                .andExpect(status().isOk());
    }


    @Test
    void whenRequestHasBasicAuth_thenAuthenticateWithBasic() throws Exception {
        mockMvc.perform(get("/api/secure/mtls")
                        .header("Authorization", basicAuth("client", "wilson")))
                .andExpect(status().isOk());
    }

    @Test
    void whenRequestHasCertAndBasicAuth_thenAuthenticateWithBoth() throws Exception {
        X509Certificate mockCert = Mockito.mock(X509Certificate.class);
        Mockito.when(mockCert.getSubjectDN())
                .thenReturn(() -> "CN=client, OU=test, O=org, C=EC");

        mockMvc.perform(get("/api/secure/mtls")
                        .requestAttr("javax.servlet.request.X509Certificate", new X509Certificate[]{mockCert})
                        .header("Authorization", basicAuth("client", "wilson")))
                .andExpect(status().isOk());
    }

    @Test
    void whenRequestWithoutAuth_thenUnauthorized() throws Exception {
        mockMvc.perform(get("/api/secure/mtls"))
                .andExpect(status().isUnauthorized());
    }

}

package com.banred.mtlsmock.filter;

import com.banred.mtlsmock.service.RedisUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class MtlsAndBasicAuthFilter extends OncePerRequestFilter {

    private final RedisUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public MtlsAndBasicAuthFilter(RedisUserDetailsService uds, PasswordEncoder encoder) {
        this.userDetailsService = uds;
        this.passwordEncoder = encoder;
    }

    private String extractCN(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.startsWith("CN=")) return part.substring(3);
        }
        return null;
    }

    private String[] decodeBasic(String authHeader) {
        String base64 = authHeader.substring("Basic ".length());
        String decoded = new String(Base64.getDecoder().decode(base64));
        return decoded.split(":", 2);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        String authHeader = request.getHeader("Authorization");

        if (certs != null && authHeader != null && authHeader.startsWith("Basic ")) {
            String cn = extractCN(certs[0]);
            String[] creds = decodeBasic(authHeader);
            String username = creds[0];
            String password = creds[1];

            if (!username.equals(cn)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Usuario y CN no coinciden");
                return;
            }

            UserDetails user = userDetailsService.loadUserByUsername(username);
            if (!passwordEncoder.matches(password, user.getPassword())) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Contraseña inválida");
                return;
            }

            UsernamePasswordAuthenticationToken token =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(token);
        }

        filterChain.doFilter(request, response);
    }
}

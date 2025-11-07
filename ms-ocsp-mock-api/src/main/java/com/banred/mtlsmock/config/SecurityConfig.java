package com.banred.mtlsmock.config;

import com.banred.mtlsmock.service.RedisUserDetailsService;
import com.banred.mtlsmock.filter.MtlsAndBasicAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final RedisUserDetailsService userDetailsService;

    public SecurityConfig(RedisUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .x509(x509 -> x509
                        .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                        .userDetailsService(userDetailsService)
                )
                .httpBasic(Customizer.withDefaults()); // habilita Basic Auth
                //.authenticationManager(authenticationManager(http.getSharedObject(AuthenticationConfiguration.class)));

        return http.build();
    }



    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) {
        PreAuthenticatedAuthenticationProvider preAuthProvider = new PreAuthenticatedAuthenticationProvider();
        preAuthProvider.setPreAuthenticatedUserDetailsService(
                new UserDetailsByNameServiceWrapper<>(userDetailsService)
        );

        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
        daoProvider.setUserDetailsService(userDetailsService);
        daoProvider.setPasswordEncoder(passwordEncoder());

        return new ProviderManager(preAuthProvider, daoProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /*

    private final RedisUserDetailsService userDetailsService;

    public SecurityConfig(RedisUserDetailsService uds) {
        this.userDetailsService = uds;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .x509(x509 -> x509.subjectPrincipalRegex("CN=(.*?)(?:,|$)")) // Solo mTLS
                .httpBasic(Customizer.withDefaults()) // Solo BasicAuth
                .addFilterBefore(new MtlsAndBasicAuthFilter(userDetailsService, passwordEncoder()),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

     */
}


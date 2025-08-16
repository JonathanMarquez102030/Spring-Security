package com.eazybytes.config;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import java.util.Collections;
import java.util.List;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

    CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler =
        new CsrfTokenRequestAttributeHandler();

    http.sessionManagement(sessionConfig ->
        sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    );

    //Adding CORS security Config
    http.cors(corsConfigurer -> corsConfigurer.configurationSource(
        new CorsConfigurationSource() {
          @Override
          public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
            corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
            corsConfiguration.setAllowCredentials(true);
            corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
            corsConfiguration.setExposedHeaders(List.of("Authorization"));
            corsConfiguration.setMaxAge(7200L);

            return corsConfiguration;
          }
        }));

    //Adding CSRF configuration
    http.csrf(csrfConfig ->
            csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                .ignoringRequestMatchers("/register", "/contact", "/apiLogin")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        )
        .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);


    http.requiresChannel(rcc -> rcc.anyRequest()
        .requiresSecure()); // forza la comunicación mediante HTTPS solamente y no HTTP

    //Adding http requests configuration
    http.authorizeHttpRequests((requests) -> requests
        .requestMatchers("/myAccount")
        .hasRole("USER") //hasAuthority to access with specific authority
        .requestMatchers("/myBalance").hasAnyRole("USER",
            "ADMIN") //hasAnyAuthority to access with any of the different authorities
        .requestMatchers("/myLoans").authenticated()
        .requestMatchers("/myCards").hasRole("USER")
        .requestMatchers("/user").authenticated()
        .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession",
            "/apiLogin")
        .permitAll());

    http.oauth2ResourceServer(
        rsc -> rsc.jwt(
            jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));

    // Configura el manejo global de excepciones de autenticación y autorización
    http.exceptionHandling(ehc ->
        // Configura el manejo global de excepciones de seguridad:
        // - Establece un manejador personalizado para errores de acceso denegado
        // - Permite respuestas personalizadas cuando el usuario no tiene permisos
        ehc.accessDeniedHandler(new CustomAccessDeniedHandler())
    );
    return http.build();
  }
}

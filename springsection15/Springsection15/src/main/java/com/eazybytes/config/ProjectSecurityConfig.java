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

/**
 * Configuración de seguridad para el perfil no productivo ("!prod").
 * <p>
 * Esta clase está pensada como guía de aprendizaje para comprender cómo se arma la
 * cadena de filtros de Spring Security y cómo se configuran las principales
 * preocupaciones de seguridad: sesiones, CORS, CSRF, filtros personalizados,
 * reglas de autorización y manejo de excepciones.
 */
@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {

  /**
   * Define la cadena principal de filtros de seguridad y todas las políticas asociadas.
   * <p>
   * Orden de configuración (importante para entender el flujo):
   * 1) Sesiones sin estado (stateless) para trabajar con JWT.
   * 2) CORS para permitir peticiones desde el front (Angular en localhost:4200).
   * 3) CSRF con cookie y handler, ignorando ciertos endpoints públicos.
   * 4) Registro de filtros personalizados (validación, logging, JWT, CSRF cookie).
   * 5) Reglas de autorización por endpoint/rol.
   * 6) Form login (para pruebas) y HTTP Basic con entry point personalizado.
   * 7) Manejadores globales de excepciones (AccessDenied, etc.).
   * <p>
   * Nota: No se modifica el comportamiento original; sólo se reorganiza para lectura.
   */
  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

    // 1) Sesión stateless
    configureSessionStateless(http);

    // 2) CORS
    configureCors(http);

    // 3) CSRF
    configureCsrf(http);

    // 4) Filtros personalizados (incluye el filtro que escribe la cookie CSRF)
    registerCustomFilters(http);

    // 5) Autorizaciones por endpoint
    configureAuthorization(http);

    // 6) Servidor de Recursos OAuth2 (JWT):
    //    - Habilita la validación de tokens Bearer entrantes y la construcción del Authentication desde el JWT.
    //    - Usa JwtAuthenticationConverter con KeycloakRoleConverter para traducir claims de roles a GrantedAuthority ("ROLE_*"),
    //      de modo que las reglas de autorización funcionen con hasRole/hasAnyRole.
    //    - Requiere tener configurado issuer o jwk-set-uri y que el cliente envíe Authorization: Bearer <token>.
    configureOAuth2ResourceServer(http);

    // 7) Manejo global de excepciones (AccessDenied, etc.)
    configureExceptionHandling(http);

    return http.build();
  }

  /**
   * Configura la política de sesión como STATELESS (sin estado), ideal para APIs con JWT.
   */
  private void configureSessionStateless(HttpSecurity http) throws Exception {
    http.sessionManagement(
        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
  }

  /**
   * Configura CORS para permitir peticiones desde el front-end (por defecto localhost:4200).
   * Se exponen encabezados como Authorization y se habilitan credenciales cuando aplica.
   */
  private void configureCors(HttpSecurity http) throws Exception {
    http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
  }

  /**
   * Fuente de configuración CORS. Mantiene el comportamiento original.
   */
  private CorsConfigurationSource corsConfigurationSource() {
    return new CorsConfigurationSource() {
      @Override
      public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
        corsConfiguration.setExposedHeaders(List.of("Authorization"));
        corsConfiguration.setMaxAge(3600L);
        return corsConfiguration;
      }
    };
  }

  /**
   * Configura protección CSRF con cookie legible por el cliente (HttpOnly=false)
   * y define endpoints que se ignoran (públicos) para facilitar el onboarding o pruebas.
   */
  private void configureCsrf(HttpSecurity http) throws Exception {
    CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();

    http.csrf(csrf -> csrf
        .csrfTokenRequestHandler(csrfHandler)
        .ignoringRequestMatchers("/register", "/contact")
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    );
  }

  /**
   * Registra los filtros personalizados conservando el mismo orden relativo
   * que el código original (esto es crítico para no alterar el comportamiento):
   * - RequestValidationBeforeFilter: antes de BasicAuthenticationFilter
   * - AuthoritiesLoggingAtFilter: en la posición de BasicAuthenticationFilter
   * - AuthoritiesLoggingAfterFilter: después de BasicAuthenticationFilter
   * - JWTTokenValidatorFilter: antes de BasicAuthenticationFilter (valida JWT entrante)
   * - JWTTokenGeneratorFilter: después de BasicAuthenticationFilter (emite JWT saliente)
   * - CsrfCookieFilter: después de BasicAuthenticationFilter (envía cookie CSRF)
   */
  private void registerCustomFilters(HttpSecurity http) throws Exception {
    http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
  }

  /**
   * Define reglas de autorización por endpoint y rol/autoridad.
   */
  private void configureAuthorization(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(requests -> requests
        .requestMatchers("/myAccount").hasRole("USER")
        .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
        .requestMatchers("/myLoans").authenticated()
        .requestMatchers("/myCards").hasRole("USER")
        .requestMatchers("/user").authenticated()
        .requestMatchers("/notices", "/contact", "/error", "/register").permitAll()
    );
  }

  /**
   * Configura este servicio como un OAuth2 Resource Server basado en JWT.
   *
   * Qué hace:
   * - Activa la validación y extracción de autenticación desde tokens JWT entrantes
   *   (oauth2ResourceServer().jwt()).
   * - Define cómo convertir los claims del token en autoridades de Spring (GrantedAuthority)
   *   mediante un JwtAuthenticationConverter que delega en {@code KeycloakRoleConverter}.
   *
   * Para qué:
   * - Permite proteger endpoints usando roles/authorities incluidos en el JWT emitido por
   *   un IdP (por ejemplo, Keycloak) y evaluarlos con las reglas de
   *   {@link #configureAuthorization(HttpSecurity)}.
   * - Facilita arquitecturas stateless típicas de APIs REST donde no hay sesión de servidor.
   *
   * Cómo:
   * 1) Crea un JwtAuthenticationConverter.
   * 2) Configura un converter de autoridades que lee los claims específicos del proveedor
   *    (p. ej., realm_access/resource_access en Keycloak) y los mapea a autoridades con el
   *    prefijo/formato esperado por Spring (p. ej., "ROLE_USER").
   * 3) Registra dicho converter en la configuración JWT del Resource Server para que Spring
   *    lo use al construir el Authentication del request.
   *
   * Requisitos de entorno:
   * - Definir el issuer o jwk-set-uri en la configuración de la aplicación para validar la firma.
   * - Enviar Authorization: Bearer <JWT> en cada petición a endpoints protegidos.
   *
   * Notas:
   * - Aquí no se generan tokens; solo se validan y se extraen autoridades.
   * - Si cambia el proveedor o el formato de claims, ajusta {@code KeycloakRoleConverter} para
   *   mapear correctamente a GrantedAuthority.
   */
  private void configureOAuth2ResourceServer(HttpSecurity http) throws Exception {
    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
    http.oauth2ResourceServer(
        rsc -> rsc.jwt(
            jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
  }

  /**
   * Configura el manejador global para errores de autorización (403/AccessDenied).
   */
  private void configureExceptionHandling(HttpSecurity http) throws Exception {
    http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
  }
}

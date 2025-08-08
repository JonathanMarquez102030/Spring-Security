package com.eazybytes.config;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Configuración de seguridad para el perfil no productivo ("!prod").
 *
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
   *
   * Orden de configuración (importante para entender el flujo):
   * 1) Sesiones sin estado (stateless) para trabajar con JWT.  
   * 2) CORS para permitir peticiones desde el front (Angular en localhost:4200).  
   * 3) CSRF con cookie y handler, ignorando ciertos endpoints públicos.  
   * 4) Registro de filtros personalizados (validación, logging, JWT, CSRF cookie).  
   * 5) Reglas de autorización por endpoint/rol.  
   * 6) Form login (para pruebas) y HTTP Basic con entry point personalizado.  
   * 7) Manejadores globales de excepciones (AccessDenied, etc.).
   *
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

    // 6) Form login y HTTP Basic (con entry point personalizado)
    configureFormLogin(http);
    configureHttpBasic(http);

    // 7) Manejo global de excepciones (AccessDenied, etc.)
    configureExceptionHandling(http);

    return http.build();
  }

  /**
   * Configura la política de sesión como STATELESS (sin estado), ideal para APIs con JWT.
   */
  private void configureSessionStateless(HttpSecurity http) throws Exception {
    http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
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
        .ignoringRequestMatchers("/register", "/contact", "/apiLogin")
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
    http.addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class);
    http.addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class);
    http.addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class);
    http.addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class);
    http.addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class);
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
        .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession", "/apiLogin").permitAll()
    );
  }

  /**
   * Habilita el formulario de login por defecto (útil para pruebas/manual testing).
   */
  private void configureFormLogin(HttpSecurity http) throws Exception {
    http.formLogin(withDefaults());
  }

  /**
   * Configura HTTP Basic con un entry point personalizado que devuelve
   * respuestas de error con formato JSON.
   */
  private void configureHttpBasic(HttpSecurity http) throws Exception {
    http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
  }

  /**
   * Configura el manejador global para errores de autorización (403/AccessDenied).
   */
  private void configureExceptionHandling(HttpSecurity http) throws Exception {
    http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
  }

  /**
   * Provee un PasswordEncoder delegante, que permite múltiples formatos/hash y
   * antepone el identificador del esquema (por ejemplo {bcrypt}). Recomendado por Spring Security.
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  /**
   * Verificador de contraseñas comprometidas (Spring Security 6.3+).
   * Usa el servicio HaveIBeenPwned para alertar sobre passwords filtradas.
   */
  @Bean
  public CompromisedPasswordChecker compromisedPasswordChecker() {
    return new HaveIBeenPwnedRestApiPasswordChecker();
  }

  /**
   * AuthenticationManager basado en un Provider personalizado que
   * valida usuario/contraseña contra la fuente definida por UserDetailsService.
   * Se desactiva el borrado de credenciales post-autenticación para facilitar
   * ciertos casos de logging/auditoría (no recomendado en producción).
   */
  @Bean
  public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                     PasswordEncoder passwordEncoder) {
    EazyBankUsernamePwdAuthenticationProvider authenticationProvider =
        new EazyBankUsernamePwdAuthenticationProvider(userDetailsService, passwordEncoder);

    ProviderManager providerManager = new ProviderManager(Collections.singletonList(authenticationProvider));
    providerManager.setEraseCredentialsAfterAuthentication(false);
    return providerManager;
  }
}

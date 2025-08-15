package com.prospirance.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración de seguridad de la aplicación (guía de referencia).
 * <p>
 * Esta clase define y expone los componentes clave de Spring Security para aplicaciones web:
 * <ul>
 *   <li>Un SecurityFilterChain que determina cómo se protegen las rutas (autorización) y qué
 *       mecanismos de autenticación están activos.</li>
 *   <li>Soporte para autenticación mediante login por formulario (usuario/contraseña) y
 *       autenticación con proveedores externos vía OAuth2.</li>
 *   <li>Un repositorio en memoria de clientes OAuth2 para que Spring Security sepa qué
 *       proveedores externos están disponibles (por ejemplo, GitHub y Facebook).</li>
 * </ul>
 * Buenas prácticas:
 * <ul>
 *   <li>Evitar hardcodear credenciales. Utilizar variables de entorno o archivos de configuración.</li>
 *   <li>Proteger rutas sensibles con authenticated() o con verificaciones de rol/autoridad.</li>
 *   <li>Centralizar aquí la configuración de seguridad para facilitar el mantenimiento y pruebas.</li>
 * </ul>
 */
@Configuration
public class ProjectSecurityConfig {

  /**
   * Define la cadena de filtros de seguridad y las reglas de autorización HTTP.
   * <p>
   * Qué hace:
   * <ul>
   *   <li>Protege la ruta "/secure" exigiendo un usuario autenticado.</li>
   *   <li>Permite el acceso a cualquier otra ruta sin autenticación.</li>
   *   <li>Habilita login por formulario con la configuración por defecto de Spring Security.</li>
   *   <li>Habilita login mediante OAuth2 (proveedores externos) con configuración por defecto.</li>
   * </ul>
   * Cómo usar/adaptar:
   * <ul>
   *   <li>Para proteger más rutas, añade más requestMatchers(...).authenticated() o reglas con roles
   *       como hasRole("ADMIN")/hasAuthority("...").</li>
   *   <li>Para un formulario de login custom, usa http.formLogin(form -> form.loginPage("/mi-login")).</li>
   *   <li>Para personalizar OAuth2 (páginas de éxito/fracaso, scopes), usa http.oauth2Login(o -> ...).</li>
   * </ul>
   *
   * @param http builder para configurar seguridad HTTP (autorización y autenticación)
   * @return la cadena de filtros de seguridad construida y lista para usarse por el framework
   * @throws Exception si ocurre algún problema al construir la configuración
   */
  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorizeRequests ->
        authorizeRequests.requestMatchers("/secure").authenticated()
            .anyRequest().permitAll()
    );

    // Habilita el login por formulario con valores por defecto (ruta /login, etc.).
    http.formLogin(Customizer.withDefaults());

    // Habilita OAuth2 Login (GitHub, Facebook, etc.) con valores por defecto.
    http.oauth2Login(Customizer.withDefaults());

    return http.build();
  }

  /**
   * Repositorio de registros de clientes OAuth2 en memoria.
   * <p>
   * Qué hace:
   * <ul>
   *   <li>Registra los proveedores externos disponibles para OAuth2 Login.</li>
   *   <li>Permite a Spring Security resolver la configuración de cada proveedor (clientId, secretos, endpoints).</li>
   * </ul>
   * Cuándo usar:
   * <ul>
   *   <li>Útil para demos, pruebas o configuraciones simples.</li>
   *   <li>En producción, considera externalizar a properties o a un repositorio persistente.</li>
   * </ul>
   *
   * @return un repositorio en memoria con las configuraciones de GitHub y Facebook
   */
  @Bean
  ClientRegistrationRepository clientRegistrationRepository() {
    ClientRegistration githubClientRegistration = githubClientRegistration();
    ClientRegistration facebookClientRegistration = facebookClientRegistration();
    return new InMemoryClientRegistrationRepository(githubClientRegistration,
        facebookClientRegistration);
  }

  /**
   * Registro de cliente OAuth2 para GitHub.
   * <p>
   * Qué hace:
   * <ul>
   *   <li>Construye una configuración de cliente usando CommonOAuth2Provider.GITHUB, que ya trae
   *       endpoints y scopes típicos preconfigurados.</li>
   * </ul>
   * Nota de seguridad: evita exponer clientId/clientSecret en el código. Cárgalos desde
   * propiedades o variables de entorno.
   *
   * @return un ClientRegistration listo para usarse en oauth2Login con GitHub
   */
  private ClientRegistration githubClientRegistration() {
    return CommonOAuth2Provider.GITHUB.getBuilder("github").clientId("Ov23li7hVP9vsATSnwKO")
        .clientSecret("052447809a970293900a54f9aa881746113e5bd1").build();
  }

  /**
   * Registro de cliente OAuth2 para Facebook.
   * <p>
   * Qué hace:
   * <ul>
   *   <li>Construye una configuración de cliente usando CommonOAuth2Provider.FACEBOOK, con valores
   *       por defecto de endpoints/scopes.</li>
   * </ul>
   * Nota de seguridad: evita exponer clientId/clientSecret en el código. Cárgalos desde
   * propiedades o variables de entorno.
   *
   * @return un ClientRegistration listo para usarse en oauth2Login con Facebook
   */
  private ClientRegistration facebookClientRegistration() {
    return CommonOAuth2Provider.FACEBOOK.getBuilder("facebook").clientId("1324986002519262")
        .clientSecret("da9913105d2b373c2a79067c635177e2").build();
  }


}

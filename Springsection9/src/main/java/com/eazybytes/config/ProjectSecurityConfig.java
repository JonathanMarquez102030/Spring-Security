package com.eazybytes.config;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
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
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler =
        new CsrfTokenRequestAttributeHandler();

    // Esta configuración se utiliza para que Spring Security no guarde
    // explícitamente la información de la sesión en la base de datos.
    // De esta manera, Spring Security no se encargará de guardar la
    // información de la sesión en la base de datos, lo que mejora el rendimiento
    // de la aplicación.
    http.securityContext(contextConfig ->
        contextConfig.requireExplicitSave(false));
    http.sessionManagement(sessionConfig ->
        sessionConfig.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
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
            corsConfiguration.setMaxAge(3600L);

            return corsConfiguration;
          }
        }));

    //Adding CSRF configuration
    http.csrf(csrfConfig ->
            csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                .ignoringRequestMatchers("/register", "/contact")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        )
        .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);

    //Adding session management configuration
    http.sessionManagement(smc ->
             smc.invalidSessionUrl("/invalidSession").maximumSessions(3) //Invalida nuevas sesiones cuando se llega al maximo de sesiones, en lugar de cerrar la anterior
                .maxSessionsPreventsLogin(true))
                .requiresChannel(rcc ->
                    rcc.anyRequest().requiresInsecure()); // permite solo peticiones de HTTP y no HTTPS

    //Adding http requests configuration
    http.authorizeHttpRequests((requests) -> requests
        .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT") //hasAuthority to access with specific authority
        .requestMatchers( "/myBalance").hasAnyAuthority("VIEWBALANCE", "VIEWACCOUNT") //hasAnyAuthority to access with any of the different authorities
        .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
        .requestMatchers("/user").authenticated()
        .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession")
        .permitAll());

    http.formLogin(withDefaults());

    http.httpBasic(hbc ->
        // - Establece un punto de entrada personalizado para manejar errores de autenticación
        // - Proporciona una respuesta JSON personalizada con detalles del error
        hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint())
    );

    // Configura el manejo global de excepciones de autenticación y autorización
    http.exceptionHandling(ehc ->
        // Configura el manejo global de excepciones de seguridad:
        // - Establece un manejador personalizado para errores de acceso denegado
        // - Permite respuestas personalizadas cuando el usuario no tiene permisos
        ehc.accessDeniedHandler(new CustomAccessDeniedHandler())
    );
    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  /**
   * From Spring Security 6.3 version
   *
   * @return
   */
  @Bean
  public CompromisedPasswordChecker compromisedPasswordChecker() {
    return new HaveIBeenPwnedRestApiPasswordChecker();
  }

}

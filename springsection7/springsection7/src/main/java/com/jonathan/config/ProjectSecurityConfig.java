package com.jonathan.config;

import com.jonathan.exceptionhandling.CustomAccessDeniedHandler;
import com.jonathan.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    //Defines the strategy to pretect the application of session fixation attacks by default is change session id
    http.sessionManagement(session ->
        session.sessionFixation(sfc -> sfc.changeSessionId())
    );
    http
//        .sessionManagement(session -> session.invalidSessionUrl("/invalidSession")) // for mvc applications
        .sessionManagement(session -> session.maximumSessions(1) // Set a maximum number of simultaneous sessions per user
            .maxSessionsPreventsLogin(true) // avoid login if the maximum sessions are reached
        )
        .csrf(csrfConfig -> csrfConfig.disable())
        .authorizeHttpRequests(
            (requests) -> requests
                .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards")
                .authenticated()
                .requestMatchers("/notices", "/contact", "/error", "/register", "/invalidSession").permitAll()
        );
    http.formLogin(withDefaults());
    http.httpBasic(httpBasicConfigurer ->
        httpBasicConfigurer.authenticationEntryPoint(
            new CustomBasicAuthenticationEntryPoint()
        )
    );
//    http.exceptionHandling(
//        exceptionHandlingConfigurer -> exceptionHandlingConfigurer.authenticationEntryPoint(
//            new CustomBasicAuthenticationEntryPoint())); //it is a global config
    http.exceptionHandling(exceptionHandlingConfigurer ->
        exceptionHandlingConfigurer.accessDeniedHandler(new CustomAccessDeniedHandler()
        )
    );
    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }


  @Bean
  public CompromisedPasswordChecker compromisedPasswordChecker() {
    return new HaveIBeenPwnedRestApiPasswordChecker();
  }
}

package com.jonathan.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class ProjectSecurityConfig {

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
        (requests) -> requests
            .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards")
            .authenticated()
            .requestMatchers("/notices", "/contact", "/error").permitAll()
    );
    http.formLogin(withDefaults());
//    http.formLogin(formLoginConfigurer -> formLoginConfigurer.disable());
    http.httpBasic(withDefaults());
//    http.httpBasic(httpBasicConfigurer -> httpBasicConfigurer.disable());
    return http.build();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    // {prefix} the prefix sets what kind of encoder will be used for the password
    UserDetails user = User.withUsername("user").password("{noop}user@12345").authorities("read").build();
    UserDetails admin = User.withUsername("admin")
        .password("{bcrypt}$2a$12$vAhaly2E5zeW9oFiItDSkuzfdXWvVAYQL2bLcbLe4MiCyKuYcxcbG")
        .authorities("admin").build();

    return new InMemoryUserDetailsManager(user, admin);
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

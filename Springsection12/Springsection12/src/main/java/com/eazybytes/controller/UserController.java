package com.eazybytes.controller;

import com.eazybytes.constants.ApplicationConstants;
import com.eazybytes.model.Customer;
import com.eazybytes.model.LoginRequestDto;
import com.eazybytes.model.LoginResponseDto;
import com.eazybytes.repository.CustomerRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class UserController {

  private final CustomerRepository customerRepository;
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final Environment env;

  @PostMapping("/register")
  public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
    try {
      String hashPwd = passwordEncoder.encode(customer.getPwd());
      customer.setPwd(hashPwd);
      customer.setCreateDt(new Date(System.currentTimeMillis()));
      Customer savedCustomer = customerRepository.save(customer);

      if (savedCustomer.getId() > 0) {
        return ResponseEntity.status(HttpStatus.CREATED).
            body("Given user details are successfully registered");
      } else {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).
            body("User registration failed");
      }
    } catch (Exception ex) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).
          body("An exception occurred: " + ex.getMessage());
    }
  }

  @RequestMapping("/user")
  public Customer getUserDetailsAfterLogin(Authentication authentication) {
    Optional<Customer> optionalCustomer = customerRepository.findByEmail(authentication.getName());
    return optionalCustomer.orElse(null);
  }

  @PostMapping("/apiLogin")
  public ResponseEntity<LoginResponseDto> apiLogin(@RequestBody LoginRequestDto loginRequest) {
    String jwt = "";
    Authentication authentication =
         UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(),
            loginRequest.password());

    Authentication authenticationResponse = authenticationManager.authenticate(authentication);
    if (authenticationResponse != null && authenticationResponse.isAuthenticated()) {

      // Obtiene la clave secreta para firmar el JWT desde las propiedades, con un valor por defecto
      String secret = env.getProperty(ApplicationConstants.JWT_SECRET_KEY,
          ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);

      // Crea una clave secreta a partir del string de configuración
      SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

      // Construye el JWT con la siguiente información:
      // - Emisor: "Jonathan Marquez"
      // - Asunto: "JWT Token"
      // - Reclamos personalizados: nombre de usuario y autoridades/roles
      // - Fecha de emisión: momento actual
      // - Fecha de expiración: 30,000,000 ms (aproximadamente 8.3 horas) después de la emisión
      // - Firma: usando la clave secreta generada
      jwt = Jwts.builder().issuer("Jonathan Marquez").subject("JWT Token")
          .claim("username", authenticationResponse.getName())
          .claim("authorities", authenticationResponse.getAuthorities().stream()
              .map(GrantedAuthority::getAuthority)
              .collect(Collectors.joining(","))
          )
          .issuedAt(new java.util.Date())
          .expiration(new java.util.Date(new java.util.Date().getTime() + 30000000))
          .signWith(secretKey).compact();


    }
    return ResponseEntity.status(HttpStatus.OK).header(ApplicationConstants.JWT_HEADER, jwt)
        .body(new LoginResponseDto(HttpStatus.OK.getReasonPhrase(), jwt));
  }

}

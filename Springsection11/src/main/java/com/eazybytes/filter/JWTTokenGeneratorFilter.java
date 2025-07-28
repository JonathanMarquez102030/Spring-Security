package com.eazybytes.filter;

import com.eazybytes.constants.ApplicationConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

public class JWTTokenGeneratorFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(@NonNull HttpServletRequest request, 
                                @NonNull HttpServletResponse response,
                                @NonNull FilterChain filterChain) throws ServletException, IOException {
    // Obtiene la autenticación actual del contexto de seguridad de Spring
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    // Verifica si hay un usuario autenticado
    if (authentication != null) {
      // Obtiene las propiedades de la aplicación
      Environment env = getEnvironment();

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
      String jwt = Jwts.builder().issuer("Jonathan Marquez").subject("JWT Token")
          .claim("username", authentication.getName())
          .claim("authorities", authentication.getAuthorities().stream()
              .map(GrantedAuthority::getAuthority)
              .collect(Collectors.joining(","))
          )
          .issuedAt(new Date())
          .expiration(new Date(new Date().getTime() + 30000000))
          .signWith(secretKey).compact();

      // Agrega el JWT al encabezado de la respuesta HTTP
      response.setHeader(ApplicationConstants.JWT_HEADER, jwt);
    }
    // Continúa con la cadena de filtros
    filterChain.doFilter(request, response);
  }


  /**
   * Determina si el request que se esta procesando debe ser filtrado por este
   * Filtro. En este caso, solo se filtran las peticiones que tengan como
   * servletPath a "/user".
   *
   * @param request La peticion que se esta procesando
   * @return boolean true si el request no debe ser filtrado, false en caso
   * contrario
   * @throws ServletException si ocurre un error al procesar el request
   */
  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    return !request.getServletPath().equals("/user");
  }
}

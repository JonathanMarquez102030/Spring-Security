package com.eazybytes.filter;

import com.eazybytes.constants.ApplicationConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class JWTTokenValidatorFilter extends OncePerRequestFilter {
  /**
   * @param request
   * @param response
   * @param filterChain
   * @throws ServletException
   * @throws IOException
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {
    String jwt = request.getHeader("Authorization");

    String bearer = "Bearer ";
    try {
      if (jwt != null) {
        // Obtiene las propiedades de la aplicación
        Environment env = getEnvironment();

        // Obtiene la clave secreta para firmar el JWT desde las propiedades, con un valor por defecto
        String secret = env.getProperty(ApplicationConstants.JWT_SECRET_KEY,
            ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);

        // Crea una clave secreta a partir del string de configuración
        SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        Claims claims =
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(jwt).getPayload();

        //obtiene las credenciales
        String username = String.valueOf(claims.get("username"));
        String authorities = String.valueOf(claims.get("authorities"));
        //convierte las authorities de string separadas por coma a objetos de GrantedAuthority
        List<GrantedAuthority> grantedAuthorities =
            AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);

        //crea el authentication
        Authentication authentication =
            new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);

        // Establece la autenticación actual en el SecurityContext para que la app conozca al usuario
        // y sus permisos durante esta petición (hilo actual).
        SecurityContextHolder.getContext().setAuthentication(authentication);

      }
    } catch (
        Exception e) {
      throw new BadCredentialsException("Invalid JWT Token");
    }

    filterChain.doFilter(request, response);
  }

  /**
   * Determina si el request que se esta procesando debe ser filtrado por este
   * Filtro. En este caso, solo se filtran las peticiones que NO tengan como
   * servletPath a "/user".
   *
   * @param request La petición que se esta procesando
   * @return boolean true si el request no debe ser filtrado, false en caso
   * contrario
   * @throws ServletException si ocurre un error al procesar el request
   */
  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    return request.getServletPath().equals("/user");
  }
}

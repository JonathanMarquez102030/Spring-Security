package com.eazybytes.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

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

  }

  /**
   * Determina si el request que se esta procesando debe ser filtrado por este
   * Filtro. En este caso, solo se filtran las peticiones que NO tengan como
   * servletPath a "/user".
   *
   * @param request La petición que se esta procesando
   * @return boolean true si el request no debe ser filtrado, false en caso
   *         contrario
   * @throws ServletException si ocurre un error al procesar el request
   */
  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    return request.getServletPath().equals("/user");
  }
}

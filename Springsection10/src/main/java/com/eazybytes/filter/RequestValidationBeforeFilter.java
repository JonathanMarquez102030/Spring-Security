package com.eazybytes.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class RequestValidationBeforeFilter implements Filter {
  /**
   * The <code>doFilter</code> method of the Filter is called by the container each time a request/response pair is
   * passed through the chain due to a client request for a resource at the end of the chain. The FilterChain passed
   * in to this method allows the Filter to pass on the request and response to the next entity in the chain.
   * <p>
   * A typical implementation of this method would follow the following pattern:- <br>
   * 1. Examine the request<br>
   * 2. Optionally wrap the request object with a custom implementation to filter content or headers for input
   * filtering <br>
   * 3. Optionally wrap the response object with a custom implementation to filter content or headers for output
   * filtering <br>
   * 4. a) <strong>Either</strong> invoke the next entity in the chain using the FilterChain object
   * (<code>chain.doFilter()</code>), <br>
   * 4. b) <strong>or</strong> not pass on the request/response pair to the next entity in the filter chain to block
   * the request processing<br>
   * 5. Directly set headers on the response after invocation of the next entity in the filter chain.
   *
   * @param request  The request to process
   * @param response The response associated with the request
   * @param chain    Provides access to the next filter in the chain for this filter to pass the request and response
   *                 to for further processing
   * @throws IOException      if an I/O error occurs during this filter's processing of the request
   * @throws ServletException if the processing fails for any other reason
   */
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest req = (HttpServletRequest) request;
    HttpServletResponse resp = (HttpServletResponse) response;

    String header = req.getHeader(HttpHeaders.AUTHORIZATION);
    if(header != null) {
      header = header.trim();
      if(StringUtils.startsWithIgnoreCase(header, "Basic ")) {
        byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded;
        try {
          decoded = Base64.getDecoder().decode(base64Token);
          String token = new String(decoded, StandardCharsets.UTF_8); // username:password
          int delim = token.indexOf(":");
          if(delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
          }
          String email =token.substring(0, delim);
          if(email.toLowerCase().contains("test")) {
            resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
          }
        } catch (IllegalArgumentException exception) {
          throw new BadCredentialsException("Failed to decode basic authentication token");
        }
      }
    }

    chain.doFilter(req, resp);
  }
}

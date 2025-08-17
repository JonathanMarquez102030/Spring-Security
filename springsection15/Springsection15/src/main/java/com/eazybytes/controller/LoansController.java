package com.eazybytes.controller;

import com.eazybytes.model.Customer;
import com.eazybytes.model.Loans;
import com.eazybytes.repository.CustomerRepository;
import com.eazybytes.repository.LoanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class LoansController {

  private final LoanRepository loanRepository;
  private final CustomerRepository customerRepository;

  /**
   * Uso educativo de @PostAuthorize (evaluación después de la invocación).
   * <p>
   * ¿Qué hace @PostAuthorize?
   * - Evalúa una expresión SpEL DESPUÉS de ejecutar el método y obtener el resultado.
   * - Permite tomar decisiones con base en el objeto retornado mediante la variable especial "returnObject".
   * - Útil cuando la autorización depende de datos que sólo se conocen tras obtener el resultado (p. ej., propietario del recurso).
   * <p>
   * Ejemplos de expresiones:
   * - @PostAuthorize("returnObject != null && returnObject.?[owner == authentication.name].size() > 0")
   * - @PostAuthorize("hasRole('ADMIN') or returnObject.customerId == principal.id")
   * <p>
   * Nota: Documentación general para aprender @PostAuthorize, aplicable a cualquier método donde se use.
   */
  @GetMapping("/myLoans")
  @PostAuthorize("hasRole('USER')")
  public List<Loans> getLoanDetails(@RequestParam String email) {
    Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);
    if (optionalCustomer.isEmpty()) {
      return null;
    }
    long id = optionalCustomer.get().getId();
    return loanRepository.findByCustomerIdOrderByStartDtDesc(id);
  }

}

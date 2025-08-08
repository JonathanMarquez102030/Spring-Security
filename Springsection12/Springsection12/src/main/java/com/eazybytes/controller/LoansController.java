package com.eazybytes.controller;

import com.eazybytes.model.Loans;
import com.eazybytes.repository.LoanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class LoansController {

    private final LoanRepository loanRepository;

    /**
     * Uso educativo de @PostAuthorize (evaluación después de la invocación).
     *
     * ¿Qué hace @PostAuthorize?
     * - Evalúa una expresión SpEL DESPUÉS de ejecutar el método y obtener el resultado.
     * - Permite tomar decisiones con base en el objeto retornado mediante la variable especial "returnObject".
     * - Útil cuando la autorización depende de datos que sólo se conocen tras obtener el resultado (p. ej., propietario del recurso).
     *
     * Ejemplos de expresiones:
     * - @PostAuthorize("returnObject != null && returnObject.?[owner == authentication.name].size() > 0")
     * - @PostAuthorize("hasRole('ADMIN') or returnObject.customerId == principal.id")
     *
     * Nota: Documentación general para aprender @PostAuthorize, aplicable a cualquier método donde se use.
     */
    @GetMapping("/myLoans")
//    @PostAuthorize("hasRole('ROOT')")
    public List<Loans> getLoanDetails(@RequestParam long id) {
        List<Loans> loans = loanRepository.findByCustomerIdOrderByStartDtDesc(id);
        if (loans != null) {
            return loans;
        } else {
            return null;
        }
    }

}

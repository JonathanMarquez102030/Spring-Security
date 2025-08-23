package com.eazybytes.repository;

import com.eazybytes.model.Loans;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface LoanRepository extends CrudRepository<Loans, Long> {

    /**
     * Uso educativo de @PreAuthorize (evaluación antes de la invocación).
     *
     * ¿Qué hace @PreAuthorize?
     * - Evalúa una expresión SpEL ANTES de ejecutar el método.
     * - Permite decidir si el método puede ejecutarse según el contexto de seguridad y/o parámetros.
     * - Variables útiles en SpEL: "authentication", "principal", y los nombres de parámetros con prefijo "#" (p.ej. #customerId).
     *
     * Expresiones comunes:
     * - @PreAuthorize("hasRole('USER')") o @PreAuthorize("hasAuthority('READ_LOANS')")
     * - @PreAuthorize("#customerId == principal.id")
     * - @PreAuthorize("hasAnyRole('ADMIN','MANAGER')")
     *
     * Nota: Documentación general para aprender @PreAuthorize, aplicable a cualquier método.
     */
//  @PreAuthorize("hasRole('USER')")
	List<Loans> findByCustomerIdOrderByStartDtDesc(long customerId);

}

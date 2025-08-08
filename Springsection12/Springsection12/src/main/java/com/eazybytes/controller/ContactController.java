package com.eazybytes.controller;

import com.eazybytes.model.Contact;
import com.eazybytes.repository.ContactRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.sql.Date;
import java.util.List;
import java.util.Random;

@RestController
@RequiredArgsConstructor
public class ContactController {

  private final ContactRepository contactRepository;

  /**
   * Ejemplo educativo de seguridad con @PreFilter.
   *
   * ¿Qué hace @PreFilter?
   * - Aplica un filtro sobre los argumentos de tipo Collection/array ANTES de que se invoque el método.
   * - La condición se define con SpEL (Spring Expression Language) y se evalúa por cada elemento.
   * - La variable especial "filterObject" representa el elemento actual durante el filtrado.
   * - También puedes usar objetos del contexto de seguridad como "authentication" o "principal" en la expresión.
   *
   * Casos de uso comunes:
   * - Limitar qué elementos de una lista enviada por el cliente están permitidos según reglas de negocio/seguridad.
   * - Cuando existe más de un parámetro coleccionable, usa el atributo "filterTarget" de @PreFilter para indicar cuál filtrar.
   *
   * Ejemplos de expresiones:
   * - @PreFilter("filterObject.owner == authentication.name")
   * - @PreFilter(value = "filterObject.active", filterTarget = "contacts")
   *
   * Nota: Esta documentación es general y aplica a cualquier uso de @PreFilter, no sólo a este método.
   */
  @PostMapping("/contact")
  @PreFilter("filterObject.contactName != 'Test'")
  public List<Contact> saveContactInquiryDetails(@RequestBody List<Contact> contacts) {
    if (contacts.isEmpty()) {
      return null;
    }

    Contact contact = contacts.getFirst();
    contact.setContactId(getServiceReqNumber());
    contact.setCreateDt(new Date(System.currentTimeMillis()));
    return List.of(contactRepository.save(contact));
  }

  public String getServiceReqNumber() {
    Random random = new Random();
    int ranNum = random.nextInt(999999999 - 9999) + 9999;
    return "SR" + ranNum;
  }
}

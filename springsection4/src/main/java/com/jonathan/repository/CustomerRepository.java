package com.jonathan.repository;

import com.jonathan.model.Customer;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface CustomerRepository extends CrudRepository<Customer, Long> {
  Optional<Customer> findByEmail(String email);

}

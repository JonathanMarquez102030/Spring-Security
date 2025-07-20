package com.jonathan;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
//@EntityScan("com.jonathan.model")
//@EnableJpaRepositories("com.jonathan.repository")
public class EazyBankBackendApplication {



    public static void main(String[] args) {
        SpringApplication.run(EazyBankBackendApplication.class, args);
    }

}


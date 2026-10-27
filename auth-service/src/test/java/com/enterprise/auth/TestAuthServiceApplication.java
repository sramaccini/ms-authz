package com.enterprise.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Avvia l'auth-service con PostgreSQL e Redis in container (Testcontainers): serve solo Docker.
 * - build: usato dal profilo Maven che esporta la definizione OpenAPI (fase integration-test);
 * - sviluppo: {@code mvn spring-boot:test-run} avvia il servizio senza docker compose.
 */
public class TestAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.from(AuthServiceApplication::main)
                .with(Containers.class)
                .run(args);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Containers {

        @Bean
        @ServiceConnection
        PostgreSQLContainer postgres() {
            return new PostgreSQLContainer("postgres:17");
        }

        @Bean
        @ServiceConnection(name = "redis")
        GenericContainer<?> redis() {
            return new GenericContainer<>("redis:7.4").withExposedPorts(6379);
        }
    }
}

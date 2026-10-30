package com.enterprise.bff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class BffGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(BffGatewayApplication.class, args);
    }
}

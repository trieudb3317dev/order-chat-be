package com.example.securty;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecurtyApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurtyApplication.class, args);
		System.out.println("Security Application is running...");
		System.out.println("Visit http://localhost:8008");
		System.out.println("Swagger UI: http://localhost:8008/swagger-ui/index.html");
	}

}

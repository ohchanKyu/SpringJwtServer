package com.example.JwtConfigServer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;

// JPA Auditing 기능 활성화 - BaseEntity
@EnableJpaAuditing
@EnableAsync
@SpringBootApplication
public class JwtRestServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtRestServerApplication.class, args);
	}

}

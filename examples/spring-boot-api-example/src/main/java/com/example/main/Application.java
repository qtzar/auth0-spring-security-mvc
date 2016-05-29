package com.example.main;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.PropertySource;

// Do NOT import auth0-security-context.xml.
@SpringBootApplication
@ComponentScan(basePackages = {"com.example"})
@EnableAutoConfiguration
@PropertySource("classpath:auth0.properties")
public class Application {

	public static void main(String[] args) {
		final AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext();
		ctx.register(ApplicationConfig.class);
		ctx.refresh();
		SpringApplication.run(Application.class, args);
	}
}

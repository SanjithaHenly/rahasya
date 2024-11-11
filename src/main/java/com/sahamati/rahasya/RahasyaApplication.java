package com.sahamati.rahasya;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class RahasyaApplication {

	public static void main(String[] args) {
		SpringApplication.run(RahasyaApplication.class, args);
	}

}

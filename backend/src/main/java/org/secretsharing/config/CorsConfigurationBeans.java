package org.secretsharing.config;

import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfigurationBeans {

	private static final Logger log = Logger.getLogger(CorsConfigurationBeans.class.getName());

	@Bean
	CorsWebFilter corsWebFilter(
			@Value("${secret-sharing.cors.allowed-origins:http://localhost:4200}") String allowedOrigins) {
		CorsConfiguration config = new CorsConfiguration();
		Arrays.stream(allowedOrigins.split(","))
				.map(String::trim)
				.filter(origin -> !origin.isEmpty())
				.forEach(origin -> {
					if ("*".equals(origin)) {
						config.addAllowedOriginPattern("*");
					} else {
						config.addAllowedOrigin(origin);
					}
				});
		config.addAllowedHeader(CorsConfiguration.ALL);
		config.addAllowedMethod(HttpMethod.GET);
		config.addAllowedMethod(HttpMethod.POST);
		config.addAllowedMethod(HttpMethod.OPTIONS);
		config.setAllowCredentials(false);
		config.setMaxAge(3600L);

		log.log(Level.INFO, "CORS allowed origins configured");

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return new CorsWebFilter(source);
	}
}

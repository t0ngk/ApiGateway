package com.t0ng.apigateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.addAllowedOrigin("*");  // Allow all origins
        corsConfig.addAllowedMethod("*");  // Allow all HTTP methods
        corsConfig.addAllowedHeader("*");  // Allow all headers
        corsConfig.setMaxAge(3600L);       // Set the maximum age (in seconds) of the preflight request cache

        // Create and return a CorsWebFilter with the provided configuration
        return new CorsWebFilter(source -> corsConfig);
    }
}


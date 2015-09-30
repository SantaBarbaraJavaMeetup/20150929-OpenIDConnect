package com.krooj.oauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.krooj.oauth.authorization.web.AuthorizationRequestHttpMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

/**
 * Configuration class for this server
 */
@Configuration
@ComponentScan(basePackages = {"com.krooj.oauth"})
public class AuthorizationServerConfig {

    @Bean
    public AuthorizationRequestHttpMessageConverter AuthorizationRequestHttpMessageConverter() {
        return new AuthorizationRequestHttpMessageConverter();
    }

    @Bean
    @Primary
    public Jackson2ObjectMapperBuilder objectMapperBuilder() {
        Jackson2ObjectMapperBuilder builder = new Jackson2ObjectMapperBuilder();
        builder.serializationInclusion(JsonInclude.Include.NON_NULL);
        return builder;
    }
}

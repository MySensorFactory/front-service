package com.factory.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ApiGatewayConfiguration {

    @Bean
    @ConfigurationProperties("config")
    public PathConfig pathConfig(){
        return new PathConfig();
    }
}
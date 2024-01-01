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

    @Bean
    @ConfigurationProperties("clients.user")
    public UsersClientConfig usersClientConfig(){
        return new UsersClientConfig();
    }

    @Bean
    @ConfigurationProperties("app.security")
    public AppSecurityConfig appSecurityConfig(){
        return new AppSecurityConfig();
    }

}

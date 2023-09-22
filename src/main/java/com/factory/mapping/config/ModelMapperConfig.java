package com.factory.mapping.config;

import com.factory.security.config.dto.User;
import com.factory.openapi.model.Role;
import com.factory.openapi.model.UserResponse;
import org.modelmapper.AbstractConverter;
import org.modelmapper.Converter;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Objects;
import java.util.stream.Collectors;

@Configuration
public class ModelMapperConfig {
    @Bean
    public ModelMapper modelMapper() {
        var mapper = new ModelMapper();
        mapper.addConverter(createUserRequestUserConverter());
        return mapper;
    }

    private static Converter<UserResponse, User> createUserRequestUserConverter() {
        return new AbstractConverter<>() {
            @Override
            protected User convert(UserResponse source) {
                if (Objects.isNull(source)) {
                    return null;
                }
                var result = new User();
                result.setId(source.getId());
                result.setEnabled(source.getEnabled());
                result.setPassword(source.getPassword());
                result.setEmail(source.getEmail());
                result.setName(source.getUsername());
                result.setRoles(source.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));
                return result;
            }
        };
    }
}

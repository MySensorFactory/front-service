package com.factory.security.service;

import com.factory.client.UsersClient;
import com.factory.exception.PasswordAuthException;
import com.factory.security.dto.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class RemoteUserDetailsService {

    private final UsersClient usersClient;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    public Mono<UserDetails> loadUser(final String username, final String password) throws UsernameNotFoundException {
        return usersClient.getUserDetails(username)
                .flatMap(response -> {
                    if (!passwordEncoder.matches(password,response.getPassword())) {
                        return Mono.error(new PasswordAuthException(username));
                    }
                    return Mono.just(modelMapper.map(response, User.class));
                });
    }

    public Mono<UserDetails> loadUser(final String username) throws UsernameNotFoundException {
        return usersClient.getUserDetails(username)
                .map(response -> modelMapper.map(response, User.class));
    }
}

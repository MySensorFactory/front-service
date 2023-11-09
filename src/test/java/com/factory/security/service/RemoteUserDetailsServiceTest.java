package com.factory.security.service;

import com.factory.client.UsersClient;
import com.factory.exception.PasswordAuthException;
import com.factory.openapi.model.UserResponse;
import com.factory.security.dto.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RemoteUserDetailsServiceTest {

    @Mock
    private UsersClient usersClient;

    @Mock
    private ModelMapper modelMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private RemoteUserDetailsService userDetailsService;

    @Test
    void loadUser_WithValidCredentials_ShouldReturnUserDetails() {
        // Arrange
        String username = "testUser";
        String password = "testPassword";
        UserResponse userResponse = UserResponse.builder()
                .enabled(true)
                .username(username)
                .password(password)
                .build();
        User mappedUser = new User();

        when(usersClient.getUserDetails(username)).thenReturn(Mono.just(userResponse));
        when(passwordEncoder.matches(password, userResponse.getPassword())).thenReturn(true);
        when(modelMapper.map(userResponse, User.class)).thenReturn(mappedUser);

        // Act
        Mono<UserDetails> result = userDetailsService.loadUser(username, password);

        // Assert
        StepVerifier.create(result)
                .expectNextMatches(userDetails -> userDetails instanceof User)
                .expectComplete()
                .verify();

        verify(usersClient, times(1)).getUserDetails(username);
        verify(passwordEncoder, times(1)).matches(password, userResponse.getPassword());
        verify(modelMapper, times(1)).map(userResponse, User.class);
    }

    @Test
    void loadUser_WithWrongPassword_ShouldReturnError() {
        // Arrange
        String username = "testUser";
        String password = "wrongPassword";
        UserResponse userResponse = new UserResponse();

        when(usersClient.getUserDetails(username)).thenReturn(Mono.just(userResponse));
        when(passwordEncoder.matches(password, userResponse.getPassword())).thenReturn(false);

        // Act
        Mono<UserDetails> result = userDetailsService.loadUser(username, password);

        // Assert
        StepVerifier.create(result)
                .expectError(PasswordAuthException.class)
                .verify();

        verify(usersClient, times(1)).getUserDetails(username);
        verify(passwordEncoder, times(1)).matches(password, userResponse.getPassword());
        verify(modelMapper, never()).map(any(), eq(User.class));
    }
}

package com.factory.security.service;

import com.factory.security.dto.AccessToken;
import com.factory.security.dto.RefreshToken;
import com.factory.security.dto.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    public static final String NEW_ACCESS_TOKEN = "newAccessToken";
    public static final String TEST_USER = "testUser";
    public static final String NEW_REFRESH_TOKEN = "newRefreshToken";
    public static final String VALID_TOKEN = "validToken";
    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RemoteUserDetailsService userDetailsService;

    @InjectMocks
    private TokenService tokenService;

    @Test
    void generateRefreshToken_WithValidRefreshToken_ShouldGenerateRefreshToken() {
        // Arrange
        RefreshToken refreshToken = RefreshToken.builder().token(VALID_TOKEN).build();
        User user = new User();

        when(jwtTokenProvider.getUsernameFromRefreshToken(refreshToken)).thenReturn(TEST_USER);
        when(userDetailsService.loadUser(TEST_USER)).thenReturn(Mono.just(user));
        when(jwtTokenProvider.generateRefreshToken(user)).thenReturn(NEW_REFRESH_TOKEN);

        // Act
        Mono<RefreshToken> result = tokenService.generateRefreshToken(refreshToken);

        // Assert
        StepVerifier.create(result)
                .expectNextMatches(newRefreshToken -> newRefreshToken.getToken().equals(NEW_REFRESH_TOKEN))
                .expectComplete()
                .verify();

        verify(jwtTokenProvider, times(1)).getUsernameFromRefreshToken(refreshToken);
        verify(userDetailsService, times(1)).loadUser(TEST_USER);
        verify(jwtTokenProvider, times(1)).generateRefreshToken(user);
    }

    @Test
    void generateAccessToken_WithValidRefreshToken_ShouldGenerateAccessToken() {
        // Arrange
        RefreshToken refreshToken = RefreshToken.builder().token(VALID_TOKEN).build();
        User user = new User();

        when(jwtTokenProvider.getUsernameFromRefreshToken(refreshToken)).thenReturn(TEST_USER);
        when(userDetailsService.loadUser(TEST_USER)).thenReturn(Mono.just(user));
        when(jwtTokenProvider.generateAccessToken(user)).thenReturn(NEW_ACCESS_TOKEN);

        // Act
        Mono<AccessToken> result = tokenService.generateAccessToken(refreshToken);

        // Assert
        StepVerifier.create(result)
                .expectNextMatches(newAccessToken -> newAccessToken.getToken().equals(NEW_ACCESS_TOKEN))
                .expectComplete()
                .verify();

        verify(jwtTokenProvider, times(1)).getUsernameFromRefreshToken(refreshToken);
        verify(userDetailsService, times(1)).loadUser(TEST_USER);
        verify(jwtTokenProvider, times(1)).generateAccessToken(user);
    }
}

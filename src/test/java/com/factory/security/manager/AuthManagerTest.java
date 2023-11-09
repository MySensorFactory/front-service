package com.factory.security.manager;

import com.factory.security.dto.AccessToken;
import com.factory.security.dto.User;
import com.factory.security.service.JwtTokenProvider;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Set;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthManagerTest {

    public static final String ROLE_USER = "ROLE_USER";
    public static final String TEST_USER = "testUser";
    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private AuthManager authManager;

    @Test
    void authenticate_WithValidAccessToken_ShouldReturnAuthentication() {
        // Arrange
        String accessTokenString = "validAccessToken";
        AccessToken accessToken = AccessToken.builder().token(accessTokenString).build();
        Authentication authentication = new UsernamePasswordAuthenticationToken(null, accessTokenString, null);
        User user = User.builder()
                .name(TEST_USER)
                .roles(Set.of(ROLE_USER))
                .build();

        when(jwtTokenProvider.parseAccessToken(accessToken)).thenReturn(user);

        // Act
        Mono<Authentication> result = authManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectNextMatches(auth -> auth.getName().equals(TEST_USER) &&
                        auth.getAuthorities().size() == 1 &&
                        auth.getAuthorities().iterator().next().getAuthority().equals(ROLE_USER))
                .expectComplete()
                .verify();

        verify(jwtTokenProvider, times(1)).parseAccessToken(accessToken);
    }

    @Test
    void authenticate_WithInvalidAccessToken_ShouldReturnError() {
        // Arrange
        String accessTokenString = "invalidAccessToken";
        Authentication authentication = new UsernamePasswordAuthenticationToken(null, accessTokenString, null);

        when(jwtTokenProvider.parseAccessToken(any())).thenThrow(new ExpiredJwtException(null, null, "Token expired"));

        // Act
        Mono<Authentication> result = authManager.authenticate(authentication);

        // Assert
        StepVerifier.create(result)
                .expectError(ExpiredJwtException.class)
                .verify();

        verify(jwtTokenProvider, times(1)).parseAccessToken(any());
    }
}

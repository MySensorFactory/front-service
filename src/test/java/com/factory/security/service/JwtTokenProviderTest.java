package com.factory.security.service;

import com.factory.security.config.model.JwtConfig;
import com.factory.security.dto.AccessToken;
import com.factory.security.dto.RefreshToken;
import com.factory.security.dto.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.assertj.core.internal.bytebuddy.utility.RandomString;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

class JwtTokenProviderTest {

    public static final String TEST_USER = "testUser";
    public static final String ROLE_USER = "ROLE_USER";
    @Mock
    private JwtConfig jwtConfig;

    @InjectMocks
    private JwtTokenProvider jwtTokenProvider;

    private final String jwtSecret = getJwtSecret();

    @BeforeEach
    void setUp() {
        final long oneHour = 3600000L;
        final long thirtyDays = 2592000000L;

        MockitoAnnotations.openMocks(this);
        when(jwtConfig.getJwtSecret()).thenReturn(jwtSecret);
        when(jwtConfig.getJwtAccessTokenExpirationInMs()).thenReturn(oneHour);
        when(jwtConfig.getJwtRefreshTokenExpirationInMs()).thenReturn(thirtyDays);
    }

    private String getJwtSecret() {
        return RandomString.make(170);
    }

    @Test
    void testGenerateAccessToken() {
        User user = new User();
        user.setName(TEST_USER);
        user.setRoles(Set.of(ROLE_USER));

        String accessToken = jwtTokenProvider.generateAccessToken(user);

        assertNotNull(accessToken);
    }

    @Test
    void testGenerateRefreshToken() {
        User user = new User();
        user.setName(TEST_USER);

        String refreshToken = jwtTokenProvider.generateRefreshToken(user);

        assertNotNull(refreshToken);
    }

    @Test
    void testParseAccessToken() {
        Map<String, String> role = new HashMap<>();
        role.put("authority", ROLE_USER);
        final long oneHour = 3600000L;

        String token = generateJwtTokenForRoleAndTimePeriod(role, oneHour);

        AccessToken accessToken = new AccessToken(token);

        User parsedUser = jwtTokenProvider.parseAccessToken(accessToken);

        assertNotNull(parsedUser);
        assertEquals(TEST_USER, parsedUser.getName());
        assertEquals(Collections.singleton(ROLE_USER), parsedUser.getRoles());
    }

    private String generateJwtTokenForRoleAndTimePeriod(final Map<String, String> roles, final long period) {
        return Jwts.builder()
                .setSubject(TEST_USER)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + period))
                .claim("roles", Collections.singletonList(roles))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    @Test
    void testParseAccessTokenExpiredToken() {
        String token = getExpiredToken();

        AccessToken accessToken = new AccessToken(token);

        assertThrows(ExpiredJwtException.class, () -> jwtTokenProvider.parseAccessToken(accessToken));
    }

    private String getExpiredToken() {
        return Jwts.builder()
                .setSubject(TEST_USER)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() - 1000))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    @Test
    void testParseAccessTokenMalformedToken() {
        String token = "malformedToken";

        AccessToken accessToken = new AccessToken(token);

        assertThrows(MalformedJwtException.class, () -> jwtTokenProvider.parseAccessToken(accessToken));
    }

    @Test
    void testGetUsernameFromRefreshToken() {
        final long thirtyDays = 2592000000L;
        String token = getTokenForTimePeriod(thirtyDays);

        RefreshToken refreshToken = new RefreshToken(token);

        String username = jwtTokenProvider.getUsernameFromRefreshToken(refreshToken);

        assertEquals(TEST_USER, username);
    }

    private String getTokenForTimePeriod(final long period) {
        return Jwts.builder()
                .setSubject(TEST_USER)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + period))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    @Test
    void testGetUsernameFromRefreshTokenExpiredToken() {
        String token = getExpiredToken();

        RefreshToken refreshToken = new RefreshToken(token);

        assertThrows(ExpiredJwtException.class, () -> jwtTokenProvider.getUsernameFromRefreshToken(refreshToken));
    }

    @Test
    void testGetUsernameFromRefreshTokenMalformedToken() {
        String token = "malformedToken";

        RefreshToken refreshToken = new RefreshToken(token);

        assertThrows(MalformedJwtException.class, () -> jwtTokenProvider.getUsernameFromRefreshToken(refreshToken));
    }
}
package com.factory.security.config.filter;

import com.factory.security.config.dto.User;
import com.factory.security.service.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@RequiredArgsConstructor
public class AuthenticationJwtTokenFilter extends UsernamePasswordAuthenticationFilter {

    public static final String AUTH_DATA = "Auth-Data";
    public static final String AUTH_DATA_DELIMITER = ":";
    public static final String ACCESS_TOKEN = "Access-Token";
    public static final String REFRESH_TOKEN = "Refresh-Token";
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request,
                                                final HttpServletResponse response)
            throws AuthenticationException {
        String[] decodedToken = decodeAuthDataToken(request);
        String username = getUsername(decodedToken);
        String password = getPassword(decodedToken);
        var token = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(token);
    }

    private String getPassword(final String[] decodedToken) {
        return decodedToken[1];
    }

    private String getUsername(final String[] decodedToken) {
        return decodedToken[0];
    }

    private String[] decodeAuthDataToken(final HttpServletRequest request) {
        var authDataToken = request.getHeader(AUTH_DATA);
        byte[] decodedBytes = Base64.getDecoder().decode(authDataToken);
        String decodedToken = new String(decodedBytes, UTF_8);
        return decodedToken.split(AUTH_DATA_DELIMITER);
    }

    @Override
    protected void successfulAuthentication(final HttpServletRequest request,
                                            final HttpServletResponse response,
                                            final FilterChain chain,
                                            final Authentication authentication) {
        var user = (User) authentication.getPrincipal();
        var accessToken = jwtTokenProvider.generateAccessToken(user);
        var refreshToken = jwtTokenProvider.generateRefreshToken(user);
        response.setHeader(ACCESS_TOKEN, accessToken);
        response.setHeader(REFRESH_TOKEN, refreshToken);
    }
}

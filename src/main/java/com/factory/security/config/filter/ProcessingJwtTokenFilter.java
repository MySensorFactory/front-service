package com.factory.security.config.filter;

import com.factory.security.config.dto.AccessToken;
import com.factory.exception.ServerErrorException;
import com.factory.openapi.model.Error;
import com.factory.security.service.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class ProcessingJwtTokenFilter extends OncePerRequestFilter {
    public static final String ACCESS_TOKEN = "Access-Token";
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    @SneakyThrows
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) {
        if (isPublicEndpoint(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = request.getHeader(ACCESS_TOKEN);
        if (isTokenProvided(accessToken)) {
            try {
                var authToken = authenticateUser(accessToken);
                setAuthenticatedUser(authToken);
                filterChain.doFilter(request, response);
            } catch (final Exception e) {
                log.error("Error during access token processing: {}: stack trace: {}",
                        e.getMessage(),
                        e.getStackTrace());
                throw new ServerErrorException(Error.CodeEnum.INTERNAL_SERVER_ERROR,
                        "Error during access token processing");
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isTokenProvided(final String accessToken) {
        return Objects.nonNull(accessToken);
    }

    private boolean isPublicEndpoint(final HttpServletRequest request) {
        return request.getServletPath().equals("/login");
    }

    private void setAuthenticatedUser(final UsernamePasswordAuthenticationToken authToken) {
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    private UsernamePasswordAuthenticationToken authenticateUser(final String accessToken) {
        var user = jwtTokenProvider.parseAccessToken(AccessToken.builder().token(accessToken).build());
        var authorities = user.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
        return new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);
    }
}

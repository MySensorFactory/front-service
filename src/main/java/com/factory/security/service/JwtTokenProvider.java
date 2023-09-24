package com.factory.security.service;

import com.factory.security.config.model.JwtConfig;
import com.factory.security.dto.AccessToken;
import com.factory.security.dto.RefreshToken;
import com.factory.security.dto.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.factory.commons.Constants.AUTHORITY;
import static com.factory.commons.Constants.ROLES;


@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final JwtConfig jwtConfig;


    public String generateAccessToken(final User user) {
        Date expiryDate = getExpiryDate();

        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, jwtConfig.getJwtSecret())
                .setSubject(user.getUsername())
                .setIssuedAt(now())
                .setExpiration(expiryDate)
                .claim(ROLES, user.getAuthorities().stream().toList())
                .compact();
    }

    public String generateRefreshToken(final User user) {

        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(now())
                .setExpiration(getRefreshDate())
                .signWith(SignatureAlgorithm.HS512, jwtConfig.getJwtSecret())
                .compact();
    }

    public User parseAccessToken(final AccessToken accessToken)
            throws ExpiredJwtException {
        var user = new User();
        var claims = Jwts.parser()
                .setSigningKey(jwtConfig.getJwtSecret())
                .parseClaimsJws(accessToken.getToken())
                .getBody();
        List<Map<String, String>> roles = (List<Map<String, String>>) claims.get(ROLES);
        if (Objects.isNull(roles)){
            throw new MalformedJwtException("Cannot read roles");
        }
        user.setRoles(roles.stream().map(entry -> entry.get(AUTHORITY)).collect(Collectors.toSet()));
        user.setName(claims.getSubject());
        return user;
    }

    public String getUsernameFromRefreshToken(final RefreshToken refreshToken)
            throws ExpiredJwtException {
        return Jwts.parser()
                .setSigningKey(jwtConfig.getJwtSecret())
                .parseClaimsJws(refreshToken.getToken())
                .getBody()
                .getSubject();
    }

    private Date getRefreshDate() {
        return new Date(System.currentTimeMillis() + jwtConfig.getJwtRefreshTokenExpirationInMs());
    }

    private Date getExpiryDate() {
        return new Date(now().getTime() + jwtConfig.getJwtAccessTokenExpirationInMs());
    }

    private static Date now(){
        return new Date();
    }
}


package com.factory.security.service;

import com.factory.security.config.dto.AccessToken;
import com.factory.security.config.dto.RefreshToken;
import com.factory.security.config.dto.User;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;


@Component
public class JwtTokenProvider {

    public static final String ROLES = "roles";
    public static final String AUTHORITY = "authority";
    @Value("${app.jwtSecret}")
    private String jwtSecret;

    @Value("${app.jwtExpirationInMs}")
    private long jwtExpirationInMs;

    public String generateAccessToken(final User user) {
        Date expiryDate = getExpiryDate();

        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
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
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public User parseAccessToken(final AccessToken accessToken)
            throws ExpiredJwtException {
        var user = new User();
        var claims = Jwts.parser()
                .setSigningKey(jwtSecret)
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
                .setSigningKey(jwtSecret)
                .parseClaimsJws(refreshToken.getToken())
                .getBody()
                .getSubject();
    }

    private Date getRefreshDate() {
        return new Date(System.currentTimeMillis() + jwtExpirationInMs * 30);
    }

    private Date getExpiryDate() {
        return new Date(now().getTime() + jwtExpirationInMs);
    }

    private static Date now(){
        return new Date();
    }
}


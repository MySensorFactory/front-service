package com.factory.security.config;

import com.factory.security.config.filter.AuthenticationJwtTokenFilter;
import com.factory.security.config.filter.ProcessingJwtTokenFilter;
import com.factory.security.config.handler.CustomAccessDeniedHandler;
import com.factory.security.config.handler.CustomAuthenticationFailureHandler;
import com.factory.security.config.handler.CustomLogoutSuccessHandler;
import com.factory.security.service.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new CustomLogoutSuccessHandler();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    // @formatter:off
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        var authenticationJwtTokenFilter = new AuthenticationJwtTokenFilter(authenticationManagerBean(), jwtTokenProvider);
        http
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/counted-words").hasRole("DATA_ACCESSOR")
                    .antMatchers("/counted-words/**").hasRole("DATA_ACCESSOR")
                    .antMatchers("/login").permitAll()
                    .antMatchers("/login/**").permitAll()
                    .antMatchers("/refresh").permitAll()
                    .antMatchers("/refresh/**").permitAll()
                    .antMatchers("/v3/**").permitAll()
                    .anyRequest().authenticated()
                .and()
                .addFilter(authenticationJwtTokenFilter)
                .addFilterBefore(new ProcessingJwtTokenFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
                .httpBasic();
    }
    // @formatter:on
}

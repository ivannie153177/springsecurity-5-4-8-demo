package com.springsecurity_5_4_8.demo.security;

import com.springsecurity_5_4_8.demo.model.IgnoredUrlsProperties;
import com.springsecurity_5_4_8.demo.security.filter.DemoAuthenticationFilter;
import com.springsecurity_5_4_8.demo.security.handler.CustomAccessDeniedHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.annotation.Resource;

@Slf4j
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private IgnoredUrlsProperties ignoredUrlsProperties;

    @Resource
    private CorsConfigurationSource corsConfigurationSource;

    @Resource
    private CustomAccessDeniedHandler accessDeniedHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry = http
                .authorizeRequests();
        for (String url : ignoredUrlsProperties.getUrls()) {
            registry.antMatchers(url).permitAll();
        }

        registry
                .and()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .cors().configurationSource(corsConfigurationSource).and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler)
                .and()
                .addFilter(new DemoAuthenticationFilter(authenticationManager()));
    }

}

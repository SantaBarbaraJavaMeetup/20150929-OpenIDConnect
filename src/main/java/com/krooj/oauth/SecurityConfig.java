package com.krooj.oauth;

import com.krooj.oauth.clients.service.ClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;

/**
 * Configure spring security to protect certain endpoints.
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @EnableWebSecurity
    @Configuration
    @Order(1)
    public static class OAuthSecurityConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        private ClientService clientUserDetailsService;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                    .antMatcher("/token")
                    .authorizeRequests()
                    .antMatchers("/token")
                    .hasRole("CLIENT")
                    .and()
                    .httpBasic();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(clientUserDetailsService);
        }

    }

    @EnableWebMvcSecurity
    @Configuration
    public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.
                    authorizeRequests()
                    .antMatchers("/authorize", "/success")
                    .permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .csrf()
                    .and()
                    .formLogin()
                    .loginPage("/login")
                    .defaultSuccessUrl("/success")
                    .permitAll()
                    .and()
                    .logout()
                    .permitAll();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
        }

    }
}

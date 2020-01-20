package com.okta.examples.oauth2.pkcealways.config;

import com.okta.examples.oauth2.pkcealways.custom.CustomAuthorizationRequestResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private ClientRegistrationRepository clientRegistrationRepository;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/", "/img/**")
            .permitAll()
            .anyRequest()
            .fullyAuthenticated();

        http
            .oauth2Login()
            .authorizationEndpoint()
            .authorizationRequestResolver(new CustomAuthorizationRequestResolver(
                clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
            ));
    }
}

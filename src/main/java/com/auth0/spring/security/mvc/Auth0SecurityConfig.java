package com.auth0.spring.security.mvc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 *  Auth0 Security Config that wires together dependencies required
 *
 *  Applications are expected to extend this Config
 */
@Configuration
@EnableWebSecurity(debug = true)
@ConditionalOnProperty(prefix = "auth0", name = "defaultAuth0WebSecurityEnabled")
public class Auth0SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value(value = "${auth0.domain}")
    protected String domain;

    @Value(value = "${auth0.issuer}")
    protected String issuer;

    @Value(value = "${auth0.clientId}")
    protected String clientId;

    @Value(value = "${auth0.clientSecret}")
    protected String clientSecret;

    @Value(value = "${auth0.securedRoute}")
    protected String securedRoute;

    @Value(value = "${auth0.authorityStrategy}")
    protected String authorityStrategy;

    @Value(value = "${auth0.base64EncodedSecret}")
    protected boolean base64EncodedSecret;

    @Autowired
    @SuppressWarnings("SpringJavaAutowiringInspection")
    @Bean(name = "auth0AuthenticationManager")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public Auth0CORSFilter simpleCORSFilter() {
        return new Auth0CORSFilter();
    }

    @Bean(name = "auth0AuthenticationProvider")
    public Auth0AuthenticationProvider auth0AuthenticationProvider() {
        // First check the authority strategy configured for the API
        if (!Auth0AuthorityStrategy.contains(this.authorityStrategy)) {
            throw new IllegalStateException("Configuration error, illegal authority strategy");
        }
        final Auth0AuthorityStrategy authorityStrategy = Auth0AuthorityStrategy.valueOf(this.authorityStrategy);
        if (Auth0AuthorityStrategy.SCOPE.equals(authorityStrategy)) {
            throw new IllegalStateException("SCOPE authority strategy currently not supported for MVC apps");
        }
        final Auth0AuthenticationProvider authenticationProvider = new Auth0AuthenticationProvider();
        authenticationProvider.setDomain(domain);
        authenticationProvider.setIssuer(issuer);
        authenticationProvider.setClientId(clientId);
        authenticationProvider.setClientSecret(clientSecret);
        authenticationProvider.setSecuredRoute(securedRoute);
        authenticationProvider.setAuthorityStrategy(authorityStrategy);
        authenticationProvider.setBase64EncodedSecret(base64EncodedSecret);
        return authenticationProvider;
    }

    @Bean(name = "auth0EntryPoint")
    public Auth0AuthenticationEntryPoint auth0AuthenticationEntryPoint() {
        return new Auth0AuthenticationEntryPoint();
    }

    @Bean(name = "auth0Filter")
    public Auth0AuthenticationFilter auth0AuthenticationFilter(Auth0AuthenticationEntryPoint entryPoint) {
        final Auth0AuthenticationFilter filter = new Auth0AuthenticationFilter();
        filter.setEntryPoint(entryPoint);
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(auth0AuthenticationProvider());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        // Disable CSRF for JWT usage
        http.csrf().disable();

        // Add Auth0 Authentication Filter
        http.addFilterAfter(auth0AuthenticationFilter(auth0AuthenticationEntryPoint()), SecurityContextPersistenceFilter.class)
                .addFilterBefore(simpleCORSFilter(), Auth0AuthenticationFilter.class);

        // Apply the Authentication and Authorization Strategies your application endpoints require
        authorizeRequests(http);

        // Auth0 library will will control session management explicitly - not spring security
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
    }

    /**
     * Lightweight default configuration that offers basic authorization checks for authenticated
     * users on secured endpoint, and sets up a Principal user object with granted authorities
     * <p>
     * For simple apps, this is sufficient, however for applications wishing to specify fine-grained
     * endpoint access restrictions, use Role / Group level endpoint authorization etc, then this configuration
     * should be disabled and a copy, augmented with your own requirements provided. See Sample app for example
     *
     * Override this function in subclass to apply custom authentication / authorization
     * strategies to your application endpoints
     */
    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(securedRoute).authenticated()
                .antMatchers("/**").permitAll();
    }

}
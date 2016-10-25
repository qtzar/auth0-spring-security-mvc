package com.auth0.spring.security.mvc;

import com.auth0.SessionUtils;
import com.auth0.Tokens;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter responsible to intercept the JWT in the HTTP header and attempt an authentication.
 * It delegates the authentication to the authentication manager
 */
public class Auth0AuthenticationFilter extends GenericFilterBean {

    @Autowired
    private AuthenticationManager authenticationManager;

    private AuthenticationEntryPoint entryPoint;

    /**
     * Check for existence of id token and access token
     *
     * @param tokens the tokens object
     * @return boolean whether both id token and access token exist
     */
    protected boolean tokensExist(final Tokens tokens) {
        if (tokens == null) {
            return false;
        }
        return tokens.getIdToken() != null && tokens.getAccessToken() != null;
    }

    /**
     * Perform filter check on this request - verify tokens exist and verify
     * the id token is valid
     */
    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;
        if (request.getMethod().equals("OPTIONS")) {
            // CORS request
            chain.doFilter(request, response);
            return;
        }
        final Tokens tokens = SessionUtils.getTokens(request);
        if (tokensExist(tokens)) {
            try {
                final String jwt = tokens.getIdToken();
                final Auth0JWTToken token = new Auth0JWTToken(jwt);
                final Authentication authResult = authenticationManager.authenticate(token);
                SecurityContextHolder.getContext().setAuthentication(authResult);
            } catch (AuthenticationException failed) {
                SecurityContextHolder.clearContext();
                entryPoint.commence(request, response, failed);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    public AuthenticationEntryPoint getEntryPoint() {
        return entryPoint;
    }

    public void setEntryPoint(final AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }

}

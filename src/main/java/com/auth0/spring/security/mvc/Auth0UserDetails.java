package com.auth0.spring.security.mvc;

import com.auth0.authentication.result.UserIdentity;
import com.auth0.web.Auth0User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Implementation of Spring Security UserDetails Object
 * Spring representation of Auth0 UserProfile Object
 */
public class Auth0UserDetails implements UserDetails {

    private static final long serialVersionUID = 2058797193125711681L;

    private static final Logger logger = LoggerFactory.getLogger(Auth0UserDetails.class);

    //@TODO - add other attributes are required - make provison for access to underlying userProfile object
    // so ad-hoc attributes can also be queried?
    private String userId;
    private String username;
    private String name;
    private String email;
    private boolean emailVerified;
    private String nickname;
    private String picture;
    private Map<String, Object> extraInfo;
    private List<UserIdentity> identities;
    private ArrayList<GrantedAuthority> authorities;

    public Auth0UserDetails(final Auth0User auth0User) {
        this.userId = auth0User.getUserId();
        if (auth0User.getEmail() != null) {
            this.username = auth0User.getEmail();
        } else if (auth0User.getUserId() != null) {
            this.username = auth0User.getUserId();
        } else {
            this.username = "UNKNOWN_USER";
        }
        this.name = auth0User.getName();
        this.email = auth0User.getEmail();
        if (email != null) {
            emailVerified = auth0User.isEmailVerified();
        }
        this.nickname = auth0User.getNickname();
        this.picture = auth0User.getPicture();
        this.identities = auth0User.getIdentities();
        this.extraInfo = auth0User.getExtraInfo();
        setupAuthorities(auth0User);
    }

    /**
     *  @TODO - Configure the application to know the GrantedAuthority strategy.
     * For now, Roles takes Precedence then Groups...
     *
     * @param auth0User
     */
    private void setupAuthorities(Auth0User auth0User) {
        this.authorities = new ArrayList<>();

        if (auth0User.getRoles() != null) {
            logger.debug("Attempting to map Roles");
            try {
                for (final String role : auth0User.getRoles()) {
                    this.authorities.add(new SimpleGrantedAuthority(role));
                }
            } catch (ClassCastException e) {
                e.printStackTrace();
                logger.error("Error setting up GrantedAuthority using Roles");
            }
        } else if (auth0User.getGroups() != null) {
            logger.debug("Attempting to map Groups");
            try {
                for (final String group : auth0User.getGroups()) {
                    this.authorities.add(new SimpleGrantedAuthority(group));
                }
            } catch (ClassCastException e) {
                e.printStackTrace();
                logger.error("Error setting up GrantedAuthority using Roles");
            }
        }
        // DEFAULT in event nothing has been mapped..
        if (this.authorities.isEmpty()) {
            logger.info("Found no Roles or Groups information in UserProfile");
            this.authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getUserId() {
        return userId;
    }

    public String getNickname() {
        return nickname;
    }

    public String getPicture() {
        return picture;
    }

    public List<UserIdentity> getIdentities() {
        return identities;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * Will return UnsupportedOperationException
     */
    public String getPassword() {
        throw new UnsupportedOperationException("Password is protected");
    }

    /**
     * Gets the email if it exists otherwise it returns the user_id
     */
    public String getUsername() {
        return username;
    }

    public boolean isAccountNonExpired() {
        return false;
    }

    public boolean isAccountNonLocked() {
        return false;
    }

    public boolean isCredentialsNonExpired() {
        return false;
    }

    /**
     * Will return true if the email is verified, otherwise it will return false
     */
    public boolean isEnabled() {
        return emailVerified;
    }


}

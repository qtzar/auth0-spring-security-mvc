package com.auth0.spring.security.mvc;

import com.auth0.Auth0AuthorityStrategy;
import com.auth0.Auth0User;
import com.auth0.authentication.result.UserIdentity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

/**
 * Implementation of Spring Security UserDetails Object
 * Spring representation of Auth0 UserProfile Object
 */
public class Auth0UserDetails implements UserDetails {

    private static final long serialVersionUID = 2058797193125711681L;

    /**
     * The userId of the Auth0 normalized user profile
     */
    private String userId;

    /**
     * The username of the Auth0 normalized user profile
     */
    private String username;

    /**
     * The name assigned to the user profile
     */
    private String name;

    /**
     * The email assigned to the user profile
     */
    private String email;

    /**
     * The email verified or not
     */
    private boolean emailVerified;

    /**
     * The nickname assigned to the user profile
     */
    private String nickname;

    /**
     * The picture (gravatar) of the user profile
     */
    private String picture;

    /**
     * Extra information of the profile that is not part of the normalized profile
     * A map with user's extra information found in the profile
     */
    private Map<String, Object> extraInfo;

    /**
     * The metadata objects can be used to store additional User Profile information.
     * The user_metadata object should be used to store user attributes, such as user preferences,
     * that don't impact what a user can access
     */
    private Map<String, Object> userMetadata;

    /**
     * The metadata objects can be used to store additional User Profile information.
     * The app_metadata object should be used for user attributes, such as a support plan, security roles,
     * or access control groups, which can impact how an application functions and/or what the user can access.
     */
    private Map<String, Object> appMetadata;

    /**
     * List of the identities from a Identity Provider associated to the user.
     */
    private List<UserIdentity> identities;

    /**
     * The Granted Authorities - Spring Security specific - gets populated by matching
     * the AuthorityStrategy (ROLES or GROUPS) and populating contents of that type
     * from the input Auth0User object
     */
    private ArrayList<GrantedAuthority> authorities;

    public Auth0UserDetails(final Auth0User auth0User, final Auth0AuthorityStrategy authorityStrategy) {
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
        this.userMetadata = auth0User.getUserMetadata();
        this.appMetadata = auth0User.getAppMetadata();
        setupGrantedAuthorities(auth0User, authorityStrategy);
    }


    /**
     * Responsible for translating the GROUPS or ROLES from Auth0User into GrantedAuthority objects
     * that is used by Spring Security Framework - Currently supports Groups and Roles only
     */
    private void setupGrantedAuthorities(final Auth0User auth0User, final Auth0AuthorityStrategy authorityStrategy) {
        this.authorities = new ArrayList<>();
        if (Auth0AuthorityStrategy.ROLES.equals(authorityStrategy)) {
            if (auth0User.getRoles() != null) {
                try {
                    for (final String role : auth0User.getRoles()) {
                        this.authorities.add(new SimpleGrantedAuthority(role));
                    }
                } catch (ClassCastException e) {
                    e.printStackTrace();
                }
            }
        } else if (Auth0AuthorityStrategy.GROUPS.equals(authorityStrategy)) {
            if (auth0User.getGroups() != null) {
                try {
                    for (final String group : auth0User.getGroups()) {
                        this.authorities.add(new SimpleGrantedAuthority(group));
                    }
                } catch (ClassCastException e) {
                    e.printStackTrace();
                }
            }
        } else if (Auth0AuthorityStrategy.SCOPE.equals(authorityStrategy)) {
            throw new IllegalStateException("SCOPE authority strategy not supported for MVC apps");
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

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public Map<String, Object> getExtraInfo() {
        return Collections.unmodifiableMap(extraInfo);
    }

    public List<UserIdentity> getIdentities() {
        return Collections.unmodifiableList(identities);
    }

    public Map<String, Object> getUserMetadata() {
        return Collections.unmodifiableMap(userMetadata);
    }

    public Map<String, Object> getAppMetadata() {
        return Collections.unmodifiableMap(appMetadata);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * Will always return null
     */
    @Override
    public String getPassword() {
        return null;
    }

    /**
     * Gets the email if it exists otherwise it returns the user_id
     */
    @Override
    public String getUsername() {
        return username;
    }

    /**
     * Indicates whether the user's account has expired. An expired account cannot be
     * authenticated.
     * <p>
     * This implementation shall return true by default
     *
     * @return <code>true</code> if the user's account is valid (ie non-expired),
     * <code>false</code> if no longer valid (ie expired)
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked. A locked user cannot be
     * authenticated.
     * <p>
     * This implementation shall return true by default
     *
     * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indicates whether the user's credentials (password) has expired. Expired
     * credentials prevent authentication.
     * <p>
     * This implementation shall return true by default
     *
     * @return <code>true</code> if the user's credentials are valid (ie non-expired),
     * <code>false</code> if no longer valid (ie expired)
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Will return true if the email is verified, otherwise it will return false
     */
    @Override
    public boolean isEnabled() {
        return emailVerified;
    }


}

# Auth0 Spring Security MVC

A modern Java Spring library that allows you to use Auth0 with Spring Security for server-side MVC web apps. Leverages Spring Boot dependencies.
Validates the JWT from Auth0 in every API call to assert authentication according to configuration.

This library will allow you to write applications that:

 1. Integrate Auth0 with Spring Security - JWT Token verification on all secured endpoints and access to Principal User
 2. Are 100% Java Configuration (Annotations)
 3. Able to secure one or more URL endpoints with Role / Authority based permissions (ROLE_USER, ROLE_ADMIN etc)
 4. Able to secure Java Services using method level security annotations for role based access control
 5. Able to leverage the Spring Security JSTL tag library to add role level security to your JSP pages.


Additionally, you can also set up multiple Auth0 Spring Security web applications and configure them to work together using
Single Sign-On (SSO). if you are additionally interested in having Single Sign-On (SSO) between Java Spring Security configured
applications, then please take a look at our [auth0-spring-security-mvc-sso-sample](https://github.com/auth0-samples/auth0-spring-security-mvc-sso-sample)

Finally, note that the pattern this library depends upon is the OIDC / Oauth2 Authorization Code Grant Flow - a server-side callback
is used, and a `code` is exchanged for tokens and user profile information. Hence this library is suitable for `traditional` server-side
web applications.

If you are building a Single Page Application (SPA) using say React or Angular etc, then you should take a look at this repository
instead [https://github.com/auth0/auth0-spring-security-api](https://github.com/auth0/auth0-spring-security-api). There is an associated
sample for that project too - [auth0-spring-security-api-sample](https://github.com/auth0-samples/auth0-spring-security-api-sample)


## Download

Get Auth0 Spring Security MVC via Maven:

```xml
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>auth0-spring-security-mvc</artifactId>
  <version>0.2.0</version>
</dependency>
```

or Gradle:

```gradle
compile 'com.auth0:auth0-spring-security-mvc:0.2.0'
```

## The Oauth Server Side Protocol

This library is expected to be used in order to successfully implement the [Oauth Server Side](https://auth0.com/docs/protocols#oauth-server-side) protocol. 
This protocol is best suited for websites that need:
  
  * Authenticated Users
  * Access to 3rd party APIs on behalf of the logged in user
  
In the literature you might find this flow referred to as Authorization Code Grant. The full spec of this flow is [here.](https://tools.ietf.org/html/rfc6749#section-4.1)

## Learn how to use it

[Please read this tutorial](https://auth0.com/docs/quickstart/webapp/java-spring-security-mvc/) to learn how to use this SDK.

Perhaps the best way to learn how to use this library is to study the [Auth0 Spring Security MVC Sample](https://github.com/auth0-samples/auth0-spring-security-mvc-sample)
source code and its README file. 

Information on configuration and extension points is provided below. 

In addition to this sample for Auth0 and Spring Security integration, if you are interested in
having Single Sign-On (SSO) between Java Spring Security configured applications, then please take a look
at our [auth0-spring-security-mvc-sso-sample](https://github.com/auth0-samples/auth0-spring-security-mvc-sso-sample)
which also depends on this library.

----

## Default Configuration

Here is a listing of each of the configuration options and their meaing. If you are writing your Client application
using `Spring Boot` for example, this is as simple as dropping the following file (`auth0.properties`) into the `src/main/resources`
directory alongside `application.properties`.

Here is an example of a populated `auth0.properties` file:

```
auth0.domain:arcseldon.auth0.com
auth0.issuer: https://arcseldon.auth0.com/
auth0.clientId: eTQbNn3qxypLq2Lc1qQEThYL6R7M7MDh
auth0.clientSecret: Z3xxxxxxCB6ZMaJLOcoS94xxxxbyzGWlTvwR44fkxxxxxMCbiVtgBFFA
auth0.onLogoutRedirectTo: /login
auth0.securedRoute: /portal/*
auth0.loginCallback: /callback
auth0.loginRedirectOnSuccess: /portal/home
auth0.loginRedirectOnFail: /login
auth0.base64EncodedSecret: true
auth0.authorityStrategy: ROLES
auth0.servletFilterEnabled: false
auth0.defaultAuth0WebSecurityEnabled: false
auth0.signingAlgorithm: HS256
auth0.publicKeyPath:
```

Please take a look at the sample that accompanies this library for an easy seed project to see this working.

Here is a breakdown of what each attribute means:


`auth0.domain` - This is your auth0 domain (tenant you have created when registering with auth0 - account name)

`auth0.issuer` - This is the issuer of the JWT Token (typically full URL of your auth0 tenant account - eg. https://{tenant_name}.auth0.com/)

`auth0.clientId` - This is the client id of your auth0 application (see Settings page on auth0 dashboard)

`auth0.clientSecret` - This is the client secret of your auth0 application (see Settings page on auth0 dashboard)

`auth0.onLogoutRedirectTo` - This is the page / view that users of your site are redirected to on logout. Should start with `/`

`auth0.securedRoute`: - This is the URL pattern to secure a URL endpoint. Should start with `/` Note, if you are using the default library configuration (not overriding with
your own) which just secures a single, specific context path then this value is important. However, if you are building an application which may have several different
secured endpoints, or you don't want / need to specify an explicit configuration value in this .properties file then just set the value to something that signifies this.
Perhaps `auth0.securedRoute: UNUSED`. Then just ignore the `securedRoute` entirely when you specify your own configuration. See the section `Extending Auth0SecurityConfig`
below for further info. The takeaway message is that this property value is a convenience for the developer to configure an endpoint by context path
(.eg all URLS with `/api/v1/` in their context path) - but there is no obligation to actually reference this property in your own HttpSecurity configuration.

`auth0.loginCallback` -  This is the URL context path for the login callback endpoint. Should start with `/`

`auth0.loginRedirectOnSuccess` - This is the landing page URL context path for a successful authentication. Should start with `/`

`auth0.loginRedirectOnFail` - This is the URL context path for the page to redirect to upon failure. Should start with `/`

`auth0.base64EncodedSecret` - This is a boolean value indicating whether the Secret used to verify the JWT is base64 encoded. Default is `true`

`auth0.authorityStrategy` - This indicates whether authorization `claims` against the Principal shall be `GROUPS`, `ROLES` or `SCOPE` based. Default is `ROLES`

`auth0.servletFilterEnabled` - This is a boolean value that switches having an authentication filter enabled. Should be `false`

`auth0.defaultAuth0WebSecurityEnabled` - This is a boolean value that switches having the default config enabled. Should be `false`

The default JWT Signing Algorithm is `HS256`. This is HMAC SHA256, a symmetric crypographic algorithm (HMAC), that uses the `clientSecret` to
verify a signed JWT token. However, if you wish to configure this library to use an alternate cryptographic algorithm then use the two
options below. The Auth0 Dashboard offers the choice between `HS256` and `RS256`. 'RS256' is RSA SHA256 and uses a public key cryptographic
algorithm (RSA), that requires knowledge of the application public key to verify a signed JWT Token (that was signed with a private key).
You can download the application's public key from the Auth0 Dashboard and store it inside your application's WEB-INF directory. 

The following two attributes are required when configuring your application with this library to use `RSA` instead of `HMAC`:

`auth0.signingAlgorithm` - This is signing algorithm to verify signed JWT token. Use `HS256` or `RS256`. 

`auth0.publicKeyPath` - This is the path location to the public key stored locally on disk / inside your application War file WEB-INF directory. Should always be set when using `RS256`. 

## Extension Points in Library

Most of the library can be extended, overridden or altered according to need. Bear in mind also that this library can
be leveraged as a dependency by other libraries for features such as the Auth0CallbackHandler, NonceGenerator and SessionUtils.
But perhaps the library depending on this library has its own Security Filter solution. Because we are using Spring Security and may
wish to `deactivate` the Auth0Filter then simply set the properties entry for `auth0.servletFilterEnabled` to `false`.
This will exclude injection of the Auth0Filter when parsing the Java Spring context class.

### Auth0CallbackHandler

Designed to be very flexible, you can choose between composition and inheritance to declare a Controller that delegates
to this CallbackHandler - expects to receive an authorization code - using OIDC / Oauth2 Authorization Code Grant Flow.
Using inheritance offers full opportunities to override specific methods and use alternate implementations override specific
methods and use alternate implementations. Special Note: the base CallbackHandler, ` com.auth0.web.Auth0CallbackHandler` is
actually part of an Auth0 dependency library - see  [https://github.com/auth0/auth0-spring-mvc](https://github.com/auth0/auth0-spring-mvc)

##### Example usages

Example usage - Simply extend this class and define Controller in subclass

```
package com.auth0.example;

import com.auth0.web.Auth0CallbackHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

 @Controller
 public class CallbackController extends Auth0CallbackHandler {

     @RequestMapping(value = "${auth0.loginCallback}", method = RequestMethod.GET)
     protected void callback(final HttpServletRequest req, final HttpServletResponse res)
                                                     throws ServletException, IOException {
         super.handle(req, res);
     }
 }
```

### Extending Auth0SecurityConfig

Contained in this library is a security configuration class (using Spring Java Configuration Annotations) called `Auth0SecurityConfig`.
It handles all the library Application Context wiring configuration, and a default `HttpSecurity` endpoint configuration that by default
simply secures the URL Context path defined with `auth0.securedRoute` property (see properties configuration instructions above).

This is defined in a method called `authorizeRequests(final HttpSecurity http)` - which is intentionally meant for being overridden.
In almost all cases, it is expected that Client Applications using this library will do so.

```
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
 ```

For example, from the Sample application here is the declared subclass together with overridden method:

```
package com.auth0.example;

import com.auth0.spring.security.mvc.Auth0SecurityConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;


@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class AppConfig extends Auth0SecurityConfig {

    @Override
    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/css/**", "/fonts/**", "/js/**", "/login").permitAll()
                .antMatchers("/portal/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                .antMatchers(securedRoute).authenticated();
    }

}
```

By subclassing, and overriding `authorizeRequests` as above, you are free to define whatever endpoint security configuration (authentication and
authorization) suitable for your own needs.


## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](http://developers.auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

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
  <version>0.0.2</version>
</dependency>
```

or Gradle:

```gradle
compile 'com.auth0:auth0-spring-security-mvc:0.0.2'
```

## Learn how to use it

Right now, the best way to learn how to use this library is to study the [Auth0 Spring Security MVC Sample](https://github.com/auth0-samples/auth0-spring-security-mvc-sample)
and the README for that sample. Our official documentation shall at the link below shall be fully updated shortly, together with Maven publication of the latest release. For
dev testing, just install locally with maven to get started right away.

In addition to this sample for Auth0 and Spring Security integration, if you are additionally interested in
having Single Sign-On (SSO) between Java Spring Security configured applications, then please take a look
at our [auth0-spring-security-mvc-sso-sample](https://github.com/auth0-samples/auth0-spring-security-mvc-sso-sample)


[Please read this tutorial](https://docs.auth0.com/server-apis/java-spring-security-mvc) to learn how to use this SDK.

---

## Default Configuration

### Auth0Configuration

This holds the default Spring configuration for the library.

```
@Configuration
@EnableWebSecurity(debug = true)
@ConditionalOnProperty(prefix = "auth0", name = "defaultAuth0WebSecurityEnabled")
```

Note the above. This is meant as a light-weight configuration ok for the simplest of applications,
but it is expected that most usages of this library will involve copying this default configuration
and creating an application specific version instead. In this case, just drop the following into
one of your .properties files:

`auth0.defaultAuth0WebSecurityEnabled: false`

This disables the default configuration. The section you'll most likely wish to customize is:

```
 @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Disable CSRF for JWT usage
        http
                .csrf().disable()
                .addFilterAfter(auth0AuthenticationFilter(auth0AuthenticationEntryPoint()), SecurityContextPersistenceFilter.class)
                .addFilterBefore(simpleCORSFilter(), Auth0AuthenticationFilter.class)
                .antMatcher("/**")
                .authorizeRequests()
                .antMatchers(securedRoute).authenticated();

        // Auth0 library will will control session management explicitly - not spring security
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
    }
 ```

The above does very little other than secure the endpoint pattern provided in your configuration (.properties) for `securedRoute`.
NOTE: we also set the `sessionManagement` policy to NEVER as we wish to control this via our application (using the Auth0 library).

Here is a listing of each of the configuration options and their meaing. If you are writing your Client application
using `Spring Boot` for example, this is as simple as dropping the following file (`auth0.properties`) into the `src/main/resources`
directory alongside `application.properties`.

Here is an example:

```
auth0.domain: {DOMAIN}
auth0.clientId: {CLIENT_ID}
auth0.clientSecret: {CLIENT_SECRET}
auth0.onLogoutRedirectTo: /login
auth0.securedRoute: /portal/*
auth0.loginCallback: /callback
auth0.loginRedirectOnSuccess: /portal/home
auth0.loginRedirectOnFail: /login
auth0.servletFilterEnabled: false
auth0.defaultAuth0WebSecurityEnabled: false
```

Please take a look at the sample that accompanies this library for an easy seed project to see this working.

Here is a breakdown of what each attribute means:

`auth0.domain` - This is your auth0 domain (tenant you have created when registering with auth0 - account name)

`auth0.clientId` - This is the client id of your auth0 application (see Settings page on auth0 dashboard)

`auth0.clientSecret` - This is the client secret of your auth0 application (see Settings page on auth0 dashboard)

`auth0.onLogoutRedirectTo` - This is the page / view that users of your site are redirected to on logout. Should start with `/`

`auth0.securedRoute`: - This is the URL pattern to secure a URL endpoint. Should start with `/`

`auth0.loginCallback` -  This is the URL context path for the login callback endpoint. Should start with `/`

`auth0.loginRedirectOnSuccess` - This is the landing page URL context path for a successful authentication. Should start with `/`

`auth0.loginRedirectOnFail` - This is the URL context path for the page to redirect to upon failure. Should start with `/`

`auth0.servletFilterEnabled` - This is a boolean value that switches having an authentication filter enabled On / Off.

`auth0.defaultAuth0WebSecurityEnabled` - This is a boolean value that switches having the default config enabled On / Off.


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
methods and use alternate implementations.

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

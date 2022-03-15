<img align="right" src="https://github.com/ada-school/module-template/blob/main/ada.png">


## Spring Boot Security with JWT

Secure your REST API using Spring Security with JWT.

**Learning Objectives**

- Explain how Json Web Token(JWT) works.
- Implement the security of the API endpoints using JWT.


## Problem Solving 🤹🏽

Our API Endpoints can be used by anyone that knows the URL and API structure. In order to secure our API we are going to implement JWT authentication. But let's practice our problem solving skills first with the [Bridge Riddle](https://ed.ted.com/lessons/can-you-solve-the-bridge-riddle-alex-gendler#watch) 

**Main Topics**

* Spring Security.
* JWT.
* Token.



## Codelab 🧪

🗣️ "I hear and I forget I see and I remember I do and I understand." Confucius



### Part 1: Adding Security Configuration:

1. Add the following dependencies to your *pom.xml*:
   ```xml
      <dependency>
           <groupId>org.springframework.boot</groupId>
           <artifactId>spring-boot-starter-security</artifactId>
      </dependency>
   
      <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
      </dependency>

      <dependency>
         <groupId>org.springframework.security</groupId>
         <artifactId>spring-security-crypto</artifactId>
         <version>5.6.2</version>
      </dependency>
   ```
2. Create a new class inside the *config* package called *SecurityConfiguration* where you will define the secure and
   open endpoints and the session management policy:

   ```java
      import org.springframework.http.HttpMethod;
      import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
      import org.springframework.security.config.annotation.web.builders.HttpSecurity;
      import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
      import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
      import org.springframework.security.config.http.SessionCreationPolicy;
      
      @EnableWebSecurity
      @EnableGlobalMethodSecurity( securedEnabled = true, jsr250Enabled = true, prePostEnabled = true )
      public class SecurityConfiguration
          extends WebSecurityConfigurerAdapter
      {
      
      
          @Override
          protected void configure( HttpSecurity http )
              throws Exception
          {
              http.cors().and().csrf().disable()
                  .authorizeRequests()
                  .antMatchers( HttpMethod.GET, "/v1/health" ).permitAll()
                  .antMatchers( HttpMethod.POST,"/v1/auth" ).permitAll()
                  .anyRequest().authenticated()
                  .and()
                  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS );
          }
      }
   ```

3. Start your server and verify that the configuration works as expected:

   * Open Endpoint: [Health Controller](http://localhost:8080/v1/health)
   * Secured Endpoint: [Users' List](http://localhost:8080/v1/user)

### Part 2: Implementing the Authentication Controller

1. Create a new package called *auth* inside the *controller* package.
2. Create a new class called *LoginDto* that you will use to map the JSON send to authenticate a user:

    ```java
        public class LoginDto
         {
             String email;
         
             String password;
         
             public LoginDto( String email, String password )
             {
                 this.email = email;
                 this.password = password;
             }
         
             public String getEmail()
             {
                 return email;
             }
         
             public String getPassword()
             {
                 return password;
             }
         }
     ```
 
3. Create a new class called *TokenDto* that you will use to return the token and expiration date when the
   authentication is successful.

   ```java
      public class TokenDto
      {
      
          String token;
      
          Date expirationDate;
      
          public TokenDto( String token, Date expirationDate )
          {
              this.token = token;
              this.expirationDate = expirationDate;
          }
      
          public String getToken()
          {
              return token;
          }
      
          public Date getExpirationDate()
          {
              return expirationDate;
          }
      }
   ```
  
4. Create a new exception class inside the *exception* package called *InvalidCredentialsException*:

   ```java
      public class InvalidCredentialsException extends InternalServerErrorException
      {
         public InvalidCredentialsException()
         {
            super( new ServerErrorResponseDto( "Invalid username or password", ErrorCodeEnum.INVALID_USER_CREDENTIALS,
            HttpStatus.UNAUTHORIZED ), HttpStatus.UNAUTHORIZED );
         }
      }
    
   ```

5. Crate a new Rest Controller class inside the *controller.auth* package called *AuthController*

   ```java

   import io.jsonwebtoken.Jwts;
   import io.jsonwebtoken.SignatureAlgorithm;
   import org.ada.school.exception.InvalidCredentialsException;
   import org.ada.school.repository.document.User;
   import org.ada.school.service.UserService;
   import org.springframework.beans.factory.annotation.Autowired;
   import org.springframework.beans.factory.annotation.Value;
   import org.springframework.security.crypto.bcrypt.BCrypt;
   import org.springframework.web.bind.annotation.PostMapping;
   import org.springframework.web.bind.annotation.RequestBody;
   import org.springframework.web.bind.annotation.RequestMapping;
   import org.springframework.web.bind.annotation.RestController;
   
   import java.util.Calendar;
   import java.util.Date;
   
   import static org.ada.school.utils.Constants.CLAIMS_ROLES_KEY;
   import static org.ada.school.utils.Constants.TOKEN_DURATION_MINUTES;
   
   @RestController
   @RequestMapping( "v1/auth" )
   public class AuthController
   {
   
       @Value( "${app.secret}" )
       String secret;
   
       private final UserService userService;
   
       public AuthController( @Autowired UserService userService )
       {
           this.userService = userService;
       }
   
       @PostMapping
       public TokenDto login( @RequestBody LoginDto loginDto )
       {
           User user = userService.findByEmail( loginDto.email );
           if ( BCrypt.checkpw( loginDto.password, user.getPasswordHash() ) )
           {
               return generateTokenDto( user );
           }
           else
           {
               throw new InvalidCredentialsException();
           }
   
       }
   
       private String generateToken( User user, Date expirationDate )
       {
           return Jwts.builder()
               .setSubject( user.getId() )
               .claim( CLAIMS_ROLES_KEY, user.getRoles() )
               .setIssuedAt(new Date() )
               .setExpiration( expirationDate )
               .signWith( SignatureAlgorithm.HS256, secret )
               .compact();
       }
   
       private TokenDto generateTokenDto( User user )
       {
           Calendar expirationDate = Calendar.getInstance();
           expirationDate.add( Calendar.MINUTE, TOKEN_DURATION_MINUTES );
           String token = generateToken( user, expirationDate.getTime() );
           return new TokenDto( token, expirationDate.getTime() );
       }
   }
     ```
  
5. Add the */v1/user/* endpoint temporary to the *SecurityConfiguration* so you can access the endpoint to create a test
   user.
   ```java
    .antMatchers( HttpMethod.POST,"/v1/user" ).permitAll()
   ```
6. Verify the authentication endpoint by sending the credentials of the user created in 5.

### Part 3: Implement JWT Request Filter

This filter will help you verify the authroization token send on the request authorization header or using a Cookie.

1. Implement an *AbstractAuthenticationToken* that will facilitate the process of handling endpoints access based on
   user roles. Create a new class called *TokenAuthentication* inside the *config* package:

   ```java

   import org.springframework.security.authentication.AbstractAuthenticationToken;
   import org.springframework.security.core.GrantedAuthority;
   import org.springframework.security.core.authority.SimpleGrantedAuthority;
   
   import java.util.Collection;
   import java.util.List;
   import java.util.stream.Collectors;
   
   public class TokenAuthentication
   extends AbstractAuthenticationToken
   {
       String token;
   
       String subject;
   
       List<String> roles;
   
       public TokenAuthentication( String token, String subject, List<String> roles )
       {
           super( null );
           this.token = token;
           this.subject = subject;
           this.roles = roles;
       }
   
       @Override
       public boolean isAuthenticated()
       {
           return !token.isEmpty() && !subject.isEmpty() && !roles.isEmpty();
       }
   
       @Override
       public Object getCredentials()
       {
           return token;
       }
   
       @Override
       public Object getPrincipal()
       {
           return subject;
       }
   
       @Override
       public Collection<GrantedAuthority> getAuthorities()
       {
           return roles.stream().map( role -> new SimpleGrantedAuthority( "ROLE_" + role ) ).collect(
               Collectors.toList() );
       }
   
   
   }
   ```
 
2. Create a new class inside the *config* package called *JwtRequestFilter*:

   ```java
   import io.jsonwebtoken.Claims;
   import io.jsonwebtoken.ExpiredJwtException;
   import io.jsonwebtoken.Jws;
   import io.jsonwebtoken.Jwts;
   import io.jsonwebtoken.MalformedJwtException;
   import org.springframework.beans.factory.annotation.Value;
   import org.springframework.http.HttpHeaders;
   import org.springframework.http.HttpMethod;
   import org.springframework.http.HttpStatus;
   import org.springframework.security.core.context.SecurityContextHolder;
   import org.springframework.stereotype.Component;
   import org.springframework.web.filter.OncePerRequestFilter;
   
   import javax.servlet.FilterChain;
   import javax.servlet.ServletException;
   import javax.servlet.http.Cookie;
   import javax.servlet.http.HttpServletRequest;
   import javax.servlet.http.HttpServletResponse;
   import java.io.IOException;
   import java.util.ArrayList;
   import java.util.Arrays;
   import java.util.List;
   import java.util.Objects;
   import java.util.Optional;
   
   import static org.ada.school.utils.Constants.CLAIMS_ROLES_KEY;
   import static org.ada.school.utils.Constants.COOKIE_NAME;
   
   @Component
   public class JwtRequestFilter
   extends OncePerRequestFilter
   {
      @Value( "${app.secret}" )
      String secret;
   
       public JwtRequestFilter()
       {
       }
   
       @Override
       protected void doFilterInternal( HttpServletRequest request, HttpServletResponse response, FilterChain filterChain )
           throws ServletException, IOException
       {
           String authHeader = request.getHeader( HttpHeaders.AUTHORIZATION );
   
           if ( HttpMethod.OPTIONS.name().equals( request.getMethod() ) )
           {
               response.setStatus( HttpServletResponse.SC_OK );
               filterChain.doFilter( request, response );
           }
           else
           {
               try
               {
                   Optional<Cookie> optionalCookie =
                       request.getCookies() != null ? Arrays.stream( request.getCookies() ).filter(
                           cookie -> Objects.equals( cookie.getName(), COOKIE_NAME ) ).findFirst() : Optional.empty();
   
                   String headerJwt = null;
                   if ( authHeader != null && authHeader.startsWith( "Bearer " ) )
                   {
                       headerJwt = authHeader.substring( 7 );
                   }
                   String token = optionalCookie.isPresent() ? optionalCookie.get().getValue() : headerJwt;
   
                   if ( token != null )
                   {
                       Jws<Claims> claims = Jwts.parser().setSigningKey( secret ).parseClaimsJws( token );
                       Claims claimsBody = claims.getBody();
                       String subject = claimsBody.getSubject();
                       List<String> roles  = claims.getBody().get( CLAIMS_ROLES_KEY , ArrayList.class);
   
                       if (roles == null) {
                           response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid token roles");
                       } else {
                           SecurityContextHolder.getContext().setAuthentication( new TokenAuthentication( token, subject, roles));
                       }
   
                       request.setAttribute( "claims", claimsBody );
                       request.setAttribute( "jwtUserId", subject );
                       request.setAttribute("jwtUserRoles", roles);
   
                   }
                   filterChain.doFilter( request, response );
               }
               catch ( MalformedJwtException e )
               {
                   response.sendError( HttpStatus.BAD_REQUEST.value(), "Missing or wrong token" );
               }
               catch ( ExpiredJwtException e )
               {
                   response.sendError( HttpStatus.UNAUTHORIZED.value(), "Token expired or malformed" );
               }
           }
       }
   
   }
   ```

3.Modify the *SecurityConfiguration* class to include the *JwtRequestFilter*:

   ```java

@EnableWebSecurity
@EnableGlobalMethodSecurity( securedEnabled = true, jsr250Enabled = true, prePostEnabled = true )
public class SecurityConfiguration
        extends WebSecurityConfigurerAdapter
{

   JwtRequestFilter jwtRequestFilter;

   public SecurityConfiguration( @Autowired JwtRequestFilter jwtRequestFilter )
   {
      this.jwtRequestFilter = jwtRequestFilter;
   }

   @Override
   protected void configure( HttpSecurity http )
           throws Exception
   {
      http.addFilterBefore( jwtRequestFilter,BasicAuthenticationFilter.class ).cors().and().csrf().disable().authorizeRequests().
              antMatchers(HttpMethod.GET, "/v1/health" ).permitAll().antMatchers( HttpMethod.POST,"/v1/auth").
              permitAll().anyRequest().authenticated().and().sessionManagement().
              sessionCreationPolicy(SessionCreationPolicy.STATELESS );
   }
}  
   ```

4. Add the following annotation to the DELETE user endpoint below the *@PostMapping* annotation. This will help you
   restrict which users can perform this critical operation:
      ```properties
      @RolesAllowed("ADMIN")
      ```
5. Run the project and verify that it works as expected following these steps:
   * Start the server.
   * Send a POST request to the auth endpoint using the credentials of your test user.
   * Copy the token from the response.
   * Make a new GET request to the *user* endpoint adding the *Autorization header* with the word *Bearer* as this
     example:
      ```properties
         Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2MTMwZmMzMWYwNTk2YzE0YzRiOWY5NTMiLCJhZGFfcm9sZXMiOlsiVVNFUiJdLCJpYXQiOjE2MzA2MDAzMjAsImV4cCI6MTYzMDY4NjcyMH0.s29NZMHYDCsCXqj9W9ZajNnlwyzW4qJG832Z3PXhwhk
      ```

### Challenge Yourself: Implement a mechanism to support Application tokens

1. Implement a new method in the *AuthController* that receives an encrypted secret and verify that the secret is the
   same that you have locally using a new environment variable. If the secret match then you will generate a token that
   will allow the server to have *ADMIN* role token for 10 minutes.

   ***Tip***: Divide this problem into smaller problems. Once you solve each problem test your solution and only continue
   if it works.

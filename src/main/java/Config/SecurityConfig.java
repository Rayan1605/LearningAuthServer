package Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration // a Configuration class is a class that provides configuration to the application
// at the time of initialization or before the application starts.
public class SecurityConfig {
//So this is setting up the Authorization Server
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)  throws Exception{
//This is the default security configuration for the authorization server
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//This is setting up the open id connect
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
//This is setting up the Form login so if your not authenticated it will redirect the login form
        http.exceptionHandling((exceptions) -> exceptions.
                authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))).
               //THis below set up the Jwt
                oauth2ResourceServer((OAuth2ResourceServerConfigurer) -> OAuth2ResourceServerConfigurer.jwt(Customizer.withDefaults()));



        return http.build();
    }

}

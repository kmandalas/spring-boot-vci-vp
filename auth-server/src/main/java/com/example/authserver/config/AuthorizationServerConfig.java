package com.example.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat.SELF_CONTAINED;

@Configuration
public class AuthorizationServerConfig {

    @Order(1)
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.with(new OAuth2AuthorizationServerConfigurer(), Customizer.withDefaults());
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(oidc -> {});
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()).formLogin(withDefaults());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        Set<String> redirectUris = getRedirectUris();
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("wallet-client")
                .clientSecret("{noop}wallet-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scope("VerifiablePortableDocumentA1")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("testuser1")
                .password("pass1")
                .roles("USER")
                .build();

        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("testuser2")
                .password("pass2")
                .roles("ADMIN")
                .build();

        UserDetails user3 = User.withDefaultPasswordEncoder()
                .username("testuser3")
                .password("pass3")
                .roles("GUEST")
                .build();

        return new InMemoryUserDetailsManager(user1, user2, user3);
    }


    private static Set<String> getRedirectUris() {
        Set<String> redirectUris = new HashSet<>();
        redirectUris.add("myapp://callback");
        redirectUris.add("https://oauth.pstmn.io/v1/callback");
        return redirectUris;
    }

//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder()
//                .issuer("http://192.168.1.65:9000") // Ensure this matches your JWT iss claim
//                .build();
//    }

}

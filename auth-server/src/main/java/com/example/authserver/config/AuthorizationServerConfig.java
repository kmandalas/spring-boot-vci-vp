package com.example.authserver.config;

import com.example.authserver.wia.WalletAttestationAuthenticationConverter;
import com.example.authserver.wia.WalletAttestationAuthenticationProvider;
import com.example.authserver.wia.WalletAttestationAuthenticationToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat.SELF_CONTAINED;

@Configuration
public class AuthorizationServerConfig {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    private final WalletAttestationProperties walletAttestationProperties;
    private final String authorizationServerIssuer;

    public AuthorizationServerConfig(
            WalletAttestationProperties walletAttestationProperties,
            @Value("${spring.security.oauth2.authorizationserver.issuer}") String authorizationServerIssuer) {
        this.walletAttestationProperties = walletAttestationProperties;
        this.authorizationServerIssuer = authorizationServerIssuer;
    }

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        // Create WIA authentication components
        WalletAttestationAuthenticationConverter wiaConverter = new WalletAttestationAuthenticationConverter();
        WalletAttestationAuthenticationProvider wiaProvider = new WalletAttestationAuthenticationProvider(
                registeredClientRepository,
                walletAttestationProperties,
                authorizationServerIssuer
        );

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, authServer -> authServer
                .authorizationEndpoint(authorizationEndpoint ->
                    authorizationEndpoint.consentPage("/oauth2/consent")
                )
                // Register WIA authentication for client authentication
                .clientAuthentication(clientAuth -> clientAuth
                    .authenticationConverter(wiaConverter)
                    .authenticationProvider(wiaProvider)
                )
                // Enable PAR endpoint
                .pushedAuthorizationRequestEndpoint(withDefaults())
                .oidc(oidc -> oidc
                    .providerConfigurationEndpoint(providerConfigurationEndpoint ->
                        providerConfigurationEndpoint.providerConfigurationCustomizer(providerConfiguration ->
                            providerConfiguration.scopes(scopes -> {
                                scopes.add("eu.europa.ec.eudi.pda1_sd_jwt_vc");
                            })
                        )
                    )
                )
            )
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
            // Redirect to login page when not authenticated
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
            );

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
            .formLogin(withDefaults());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        Set<String> redirectUris = getRedirectUris();
        String clientInternalId = UUID.randomUUID().toString();
        logger.info("Creating RegisteredClientRepository with client internal ID: {}", clientInternalId);
        RegisteredClient registeredClient = RegisteredClient.withId(clientInternalId)
                .clientId("wallet-client")
                .clientSecret("{noop}wallet-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // Public client support for mobile wallets (no client secret, uses PKCE + DPoP)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                // WIA-based authentication per draft-ietf-oauth-attestation-based-client-auth
                .clientAuthenticationMethod(WalletAttestationAuthenticationToken.ATTEST_JWT_CLIENT_AUTH)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scope("eu.europa.ec.eudi.pda1_sd_jwt_vc")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(2))
                        // DPoP is handled automatically by Spring when client sends DPoP header
                        // Token will include cnf.jkt claim binding it to the DPoP key
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)  // PKCE required (S256)
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

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        logger.info("Creating InMemoryOAuth2AuthorizationService bean");
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    private static Set<String> getRedirectUris() {
        Set<String> redirectUris = new HashSet<>();
        redirectUris.add("myapp://callback");
        redirectUris.add("https://oauth.pstmn.io/v1/callback");
        return redirectUris;
    }

}

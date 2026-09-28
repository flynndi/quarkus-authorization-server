package io.quarkiverse.authorization.server.it.tokenlifecycle;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import javax.sql.DataSource;

import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.client.registration.RegistrationTokenSettingsCustomizer;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkus.arc.profile.IfBuildProfile;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;

/** Disposable JDBC fixture for cross-grant token lifecycle verification. */
@Singleton
@UnlessBuildProfile("multiple-issuers")
public class TokenLifecycleServerConfig {

    static final String REDIRECT_URI = "https://client.example/callback";
    static final String RESOURCE_OWNER = "resource-owner";
    static final String RESOURCE_OWNER_PASSWORD = "resource-owner-password";
    static final String INITIAL_ACCESS_TOKEN = "token-lifecycle-initial-access-token";

    void initialize(
            @Observes @Priority(250) StartupEvent event,
            DataSource dataSource,
            RegisteredClientRepository clients,
            OAuth2AuthorizationService authorizations)
            throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            schema(
                    connection,
                    "OAUTH2_REGISTERED_CLIENT",
                    JdbcRegisteredClientRepository.SCHEMA_LOCATION);
            schema(
                    connection,
                    "OAUTH2_AUTHORIZATION",
                    JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
            schema(
                    connection,
                    "OAUTH2_AUTHORIZATION_CONSENT",
                    JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION);
        }

        saveIfMissing(clients, resourceServer());
        saveIfMissing(clients, authorizationCodeClient());
        RegisteredClient bootstrap = saveIfMissing(clients, registrationBootstrap());
        if (authorizations.findById("registration-initial-authorization") == null) {
            Instant now = Instant.now();
            Set<String> scopes = Set.of("client.create");
            authorizations.save(
                    OAuth2Authorization.withRegisteredClient(bootstrap)
                            .id("registration-initial-authorization")
                            .principalName(bootstrap.getClientId())
                            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                            .authorizedScopes(scopes)
                            .accessToken(
                                    new OAuth2AccessToken(
                                            OAuth2AccessToken.TokenType.BEARER,
                                            INITIAL_ACCESS_TOKEN,
                                            now.minusSeconds(30),
                                            now.plus(Duration.ofHours(1)),
                                            scopes))
                            .build());
        }
    }

    @Produces
    @Singleton
    @IfBuildProfile("reference-registration")
    RegistrationTokenSettingsCustomizer registrationTokenSettings() {
        return settings -> settings.accessTokenFormat(OAuth2TokenFormat.REFERENCE);
    }

    private static RegisteredClient resourceServer() {
        return confidential("resource-server-registration", "resource-server", "resource-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    private static RegisteredClient authorizationCodeClient() {
        return confidential("code-registration", "code-client", "code-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(REDIRECT_URI)
                .scope("openid")
                .scope("profile")
                .scope("message.read")
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .tokenSettings(referenceTokens(Duration.ofMinutes(5)))
                .build();
    }

    private static RegisteredClient registrationBootstrap() {
        return RegisteredClient.withId("lifecycle-registration-bootstrap")
                .clientId("lifecycle-registration-bootstrap")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
    }

    private static RegisteredClient.Builder confidential(
            String id, String clientId, String secret) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientSecret(BcryptUtil.bcryptHash(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    private static TokenSettings referenceTokens(Duration accessTokenTtl) {
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(accessTokenTtl)
                .build();
    }

    private static RegisteredClient saveIfMissing(
            RegisteredClientRepository clients, RegisteredClient candidate) {
        RegisteredClient existing = clients.findById(candidate.getId());
        if (existing != null) {
            return existing;
        }
        clients.save(candidate);
        return candidate;
    }

    private static void schema(Connection connection, String table, String resource)
            throws SQLException {
        try (var tables = connection.getMetaData().getTables(null, null, table, new String[] { "TABLE" })) {
            if (tables.next()) {
                return;
            }
        }
        try (var statement = connection.createStatement()) {
            statement.execute("RUNSCRIPT FROM 'classpath:" + resource + "'");
        }
    }
}

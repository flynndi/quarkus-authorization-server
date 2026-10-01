package io.quarkiverse.authorization.server.it.clientcredentials;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;

import javax.sql.DataSource;

import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;

/** Disposable H2 fixture with public test credentials, not a production bootstrap or user login service. */
@Singleton
public class ClientCredentialsServerConfig {

    @Produces
    @Singleton
    RegisteredClientRepository clients(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(dataSource);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationService authorizations(DataSource dataSource, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(dataSource, clients);
    }

    void initialize(@Observes @Priority(100) StartupEvent event, DataSource dataSource,
            RegisteredClientRepository clients, AuthorizationServerSettings settings,
            @ConfigProperty(name = "test-client.jwks-origin") String jwksOrigin) throws SQLException {
        // Use the extension's schema resources; initialization belongs only to this test application.
        try (Connection connection = dataSource.getConnection()) {
            schema(connection, "OAUTH2_REGISTERED_CLIENT", JdbcRegisteredClientRepository.SCHEMA_LOCATION);
            schema(connection, "OAUTH2_AUTHORIZATION", JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        }
        if (clients.findById("machine-registration") == null) {
            clients.save(RegisteredClient.withId("machine-registration").clientId("machine-client")
                    .clientSecret(BcryptUtil.bcryptHash("machine-secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    // Declaring refresh/openid must not make Client Credentials issue refresh or ID tokens.
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .scope("message.read").scope("message.write").scope("openid")
                    .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(2)).build())
                    .build());
        }
        if (clients.findById("short-lived-registration") == null) {
            clients.save(RegisteredClient.withId("short-lived-registration").clientId("short-lived-client")
                    .clientSecret(BcryptUtil.bcryptHash("short-secret"))
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("message.read")
                    .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofSeconds(3)).build())
                    .build());
        }
        if (clients.findById("post-registration") == null) {
            clients.save(RegisteredClient.withId("post-registration").clientId("post-client")
                    .clientSecret(BcryptUtil.bcryptHash("post+secret%&=中文"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                    .scope("message.read").build());
        }
        if (clients.findById("jwt-private-registration") == null) {
            // Test fixture only: the client signs with the bundled test key, whose public key is published by this app.
            clients.save(RegisteredClient.withId("jwt-private-registration").clientId("jwt-private")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                    .clientSettings(ClientSettings.builder()
                            .jwkSetUrl(jwksOrigin + settings.getJwkSetEndpoint())
                            .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256).build())
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("message.read").build());
        }
        if (clients.findById("jwt-secret-registration") == null) {
            clients.save(RegisteredClient.withId("jwt-secret-registration").clientId("jwt-secret")
                    .clientSecret("0123456789abcdef".repeat(4))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                    .clientSettings(
                            ClientSettings.builder().tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256).build())
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("message.read").build());
        }
        if (clients.findById("legacy-registration") == null) {
            clients.save(RegisteredClient.withId("legacy-registration").clientId("legacy-client")
                    .clientSecret(BcryptUtil.bcryptHash("legacy-secret"))
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD).scope("message.read").build());
        }
        if (clients.findById("public-registration") == null) {
            clients.save(RegisteredClient.withId("public-registration").clientId("public-client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("message.read").build());
        }
    }

    private static void schema(Connection connection, String table, String resource) throws SQLException {
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

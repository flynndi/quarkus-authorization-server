package io.quarkiverse.authorization.server.it.registration;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.sql.DataSource;

import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.quarkus.runtime.StartupEvent;

/**
 * Test-only bootstrap. Target clients are created exclusively through the real registration
 * endpoint.
 */
@Singleton
@UnlessBuildProfile("multiple-issuers")
public class ClientRegistrationServerConfig {
    public static final String TOKEN_PREFIX = "registration-test-only";

    @ConfigProperty(name = "registration-test.token-prefix", defaultValue = TOKEN_PREFIX)
    String tokenPrefix;

    @Produces
    @Singleton
    OidcClientRegistrationRequestValidator registrationValidator() {
        return OidcClientRegistrationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                .andThen(OidcClientRegistrationValidator.DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
                .andThen(
                        context -> {
                            var scopes = context.request().getClientRegistration().getScopes();
                            if (scopes != null
                                    && !Set.of(
                                            "openid",
                                            "profile",
                                            "email",
                                            "message.read",
                                            "message.write")
                                            .containsAll(scopes)) {
                                throw new OAuth2AuthenticationException("invalid_scope");
                            }
                        });
    }

    void initialize(
            @Observes @Priority(300) StartupEvent event,
            DataSource dataSource,
            RegisteredClientRepository clients,
            OAuth2AuthorizationService authorizations)
            throws SQLException, IOException {
        // Schema initialization belongs to this disposable test application, never to the
        // extension.
        try (Connection connection = dataSource.getConnection()) {
            schema(
                    connection,
                    "oauth2_registered_client",
                    JdbcRegisteredClientRepository.SCHEMA_LOCATION);
            schema(
                    connection,
                    "oauth2_authorization",
                    JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
            schema(
                    connection,
                    "oauth2_authorization_consent",
                    JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION);
        }
        RegisteredClient bootstrap = clients.findById("registration-bootstrap");
        if (bootstrap == null) {
            bootstrap = RegisteredClient.withId("registration-bootstrap")
                    .clientId("registration-bootstrap")
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .build();
            clients.save(bootstrap);
        }
        for (String scenario : List.of(
                "public",
                "confidential",
                "security",
                "restart",
                "wrong-scope",
                "mixed-scope",
                "expired",
                "invalidated")) {
            String id = "initial-" + scenario;
            // An application restart must not resurrect a consumed or expired initial token.
            if (authorizations.findById(id) != null) {
                continue;
            }
            Set<String> scopes = switch (scenario) {
                case "wrong-scope" -> Set.of("openid");
                case "mixed-scope" -> Set.of("client.create", "openid");
                default -> Set.of("client.create");
            };
            Instant now = Instant.now();
            String value = this.tokenPrefix + "-" + scenario;
            authorizations.save(
                    OAuth2Authorization.withRegisteredClient(bootstrap)
                            .id(id)
                            .principalName(bootstrap.getClientId())
                            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                            .authorizedScopes(scopes)
                            .token(
                                    new OAuth2AccessToken(
                                            OAuth2AccessToken.TokenType.BEARER,
                                            value,
                                            now.minusSeconds(60),
                                            now.plusSeconds("expired".equals(scenario) ? -1 : 1800),
                                            scopes),
                                    metadata -> metadata.put(
                                            OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                            "invalidated".equals(scenario)))
                            .refreshToken(
                                    new OAuth2RefreshToken(
                                            value + "-refresh", now, now.plusSeconds(3600)))
                            .build());
        }
    }

    private static void schema(Connection connection, String table, String resource)
            throws SQLException, IOException {
        try (var tables = connection
                .getMetaData()
                .getTables(
                        null,
                        null,
                        table.toUpperCase(Locale.ROOT),
                        new String[] { "TABLE" })) {
            if (tables.next()) {
                return;
            }
        }
        try (InputStream input = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalStateException("Missing schema: " + resource);
            }
            for (String sql : new String(input.readAllBytes(), StandardCharsets.UTF_8).split(";")) {
                if (!sql.isBlank()) {
                    try (var statement = connection.createStatement()) {
                        statement.execute(sql);
                    }
                }
            }
        }
    }

    /**
     * Ensures Quarkus REST and the native authorization-server routes coexist in the same
     * application.
     */
    @Path("/unrelated")
    @UnlessBuildProfile("multiple-issuers")
    public static class UnrelatedResource {
        @GET
        public String get() {
            return "unaffected";
        }
    }
}

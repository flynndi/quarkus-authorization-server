package io.quarkiverse.authorization.server.it.tokenexchange;

import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Arrays;

import javax.sql.DataSource;

import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/** JDBC-backed fixture for end-to-end Token Exchange verification. */
@Singleton
public class TokenExchangeServerConfig {

    static final String SUBJECT_CLIENT = "subject-client";
    static final String SUBJECT_SECRET = "subject-secret";
    static final String DELEGATED_SUBJECT_CLIENT = "delegated-subject";
    static final String DELEGATED_SUBJECT_SECRET = "delegated-subject-secret";
    static final String REFERENCE_SUBJECT_CLIENT = "reference-subject";
    static final String REFERENCE_SUBJECT_SECRET = "reference-subject-secret";
    static final String SHORT_SUBJECT_CLIENT = "short-subject";
    static final String SHORT_SUBJECT_SECRET = "short-subject-secret";
    static final String ACTOR_CLIENT = "actor-client";
    static final String ACTOR_SECRET = "actor-secret";
    static final String SECOND_ACTOR_CLIENT = "second-actor";
    static final String SECOND_ACTOR_SECRET = "second-actor-secret";
    static final String WRONG_ACTOR_CLIENT = "wrong-actor";
    static final String WRONG_ACTOR_SECRET = "wrong-actor-secret";
    static final String SHORT_ACTOR_CLIENT = "short-actor";
    static final String SHORT_ACTOR_SECRET = "short-actor-secret";
    static final String JWT_EXCHANGE_CLIENT = "exchange-jwt";
    static final String JWT_EXCHANGE_SECRET = "exchange-jwt-secret";
    static final String REFERENCE_EXCHANGE_CLIENT = "exchange-reference";
    static final String REFERENCE_EXCHANGE_SECRET = "exchange-reference-secret";
    static final String RESOURCE_OWNER = "resource-owner";
    static final String RESOURCE_OWNER_PASSWORD = "resource-owner-password";

    @Produces
    @Singleton
    RegisteredClientRepository clients(DataSource dataSource, JdbcJsonCodec jsonCodec) {
        return new JdbcRegisteredClientRepository(dataSource, jsonCodec);
    }

    @Produces
    @Singleton
    OAuth2AuthorizationService authorizations(DataSource dataSource, RegisteredClientRepository clients,
            JdbcJsonCodec jsonCodec) {
        return new JdbcOAuth2AuthorizationService(dataSource, clients, jsonCodec);
    }

    void initialize(@Observes @Priority(100) StartupEvent event, DataSource dataSource,
            RegisteredClientRepository clients) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            schema(connection, "OAUTH2_REGISTERED_CLIENT", JdbcRegisteredClientRepository.SCHEMA_LOCATION);
            schema(connection, "OAUTH2_AUTHORIZATION", JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        }

        saveIfMissing(clients, passwordClient("subject-registration", SUBJECT_CLIENT, SUBJECT_SECRET,
                OAuth2TokenFormat.SELF_CONTAINED, Duration.ofMinutes(5)));
        saveIfMissing(clients, passwordClient("delegated-subject-registration", DELEGATED_SUBJECT_CLIENT,
                DELEGATED_SUBJECT_SECRET, OAuth2TokenFormat.SELF_CONTAINED, Duration.ofMinutes(5)));
        saveIfMissing(clients, passwordClient("reference-subject-registration", REFERENCE_SUBJECT_CLIENT,
                REFERENCE_SUBJECT_SECRET, OAuth2TokenFormat.REFERENCE, Duration.ofMinutes(5)));
        saveIfMissing(clients, passwordClient("short-subject-registration", SHORT_SUBJECT_CLIENT,
                SHORT_SUBJECT_SECRET, OAuth2TokenFormat.SELF_CONTAINED, Duration.ofSeconds(2)));
        saveIfMissing(clients, actorClient("actor-registration", ACTOR_CLIENT, ACTOR_SECRET,
                Duration.ofMinutes(5)));
        saveIfMissing(clients, actorClient("second-actor-registration", SECOND_ACTOR_CLIENT,
                SECOND_ACTOR_SECRET, Duration.ofMinutes(5)));
        saveIfMissing(clients, actorClient("wrong-actor-registration", WRONG_ACTOR_CLIENT,
                WRONG_ACTOR_SECRET, Duration.ofMinutes(5)));
        saveIfMissing(clients, actorClient("short-actor-registration", SHORT_ACTOR_CLIENT,
                SHORT_ACTOR_SECRET, Duration.ofSeconds(2)));
        saveIfMissing(clients, exchangeClient("exchange-jwt-registration", JWT_EXCHANGE_CLIENT,
                JWT_EXCHANGE_SECRET, OAuth2TokenFormat.SELF_CONTAINED));
        saveIfMissing(clients, exchangeClient("exchange-reference-registration", REFERENCE_EXCHANGE_CLIENT,
                REFERENCE_EXCHANGE_SECRET, OAuth2TokenFormat.REFERENCE));
        saveIfMissing(clients, actorClient("resource-server-registration", "resource-server",
                "resource-secret", Duration.ofMinutes(5)));
    }

    @Produces
    @Singleton
    IdentityProvider<UsernamePasswordAuthenticationRequest> resourceOwnerIdentityProvider() {
        return new IdentityProvider<>() {
            @Override
            public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
                return UsernamePasswordAuthenticationRequest.class;
            }

            @Override
            public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                if (!RESOURCE_OWNER.equals(request.getUsername())
                        || !Arrays.equals(RESOURCE_OWNER_PASSWORD.toCharArray(), request.getPassword().getPassword())) {
                    return Uni.createFrom().failure(new AuthenticationFailedException());
                }
                return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal(request.getUsername()))
                        .addRole("user")
                        .build());
            }
        };
    }

    @Produces
    @Singleton
    IdentityProvider<TrustedAuthenticationRequest> trustedResourceOwnerIdentityProvider() {
        return new IdentityProvider<>() {
            public Class<TrustedAuthenticationRequest> getRequestType() {
                return TrustedAuthenticationRequest.class;
            }

            public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                return RESOURCE_OWNER.equals(request.getPrincipal())
                        ? Uni.createFrom()
                                .item(QuarkusSecurityIdentity.builder()
                                        .setPrincipal(new QuarkusPrincipal(request.getPrincipal())).addRole("user").build())
                        : Uni.createFrom().nullItem();
            }
        };
    }

    private static RegisteredClient passwordClient(String id, String clientId, String secret,
            OAuth2TokenFormat format, Duration ttl) {
        return confidential(id, clientId, secret)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .scope("message.read")
                .scope("message.write")
                .tokenSettings(TokenSettings.builder().accessTokenFormat(format)
                        .accessTokenTimeToLive(ttl).build())
                .build();
    }

    private static RegisteredClient actorClient(String id, String clientId, String secret, Duration ttl) {
        return confidential(id, clientId, secret)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(ttl).build())
                .build();
    }

    private static RegisteredClient exchangeClient(String id, String clientId, String secret,
            OAuth2TokenFormat format) {
        return confidential(id, clientId, secret)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scope("message.read")
                .scope("message.write")
                .tokenSettings(TokenSettings.builder().accessTokenFormat(format)
                        .accessTokenTimeToLive(Duration.ofMinutes(5)).build())
                .build();
    }

    private static RegisteredClient.Builder confidential(String id, String clientId, String secret) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientSecret(BcryptUtil.bcryptHash(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    private static void saveIfMissing(RegisteredClientRepository clients, RegisteredClient candidate) {
        if (clients.findById(candidate.getId()) == null) {
            clients.save(candidate);
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

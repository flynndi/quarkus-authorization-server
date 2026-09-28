package io.quarkiverse.authorization.server.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.sql.DataSource;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.jackson2.OAuth2AuthorizationServerJackson2Module;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTransactionSupport;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;

/**
 * JDBC implementation of {@link RegisteredClientRepository} using an application-provided {@link DataSource}.
 * <p>
 * The extension does not expose a client management HTTP API. Applications explicitly construct or produce this
 * repository when JDBC-backed client management is required.
 */
public final class JdbcRegisteredClientRepository implements RegisteredClientRepository {

    public static final String SCHEMA_LOCATION = "META-INF/quarkus-authorization-server/schema/oauth2-registered-client-schema.sql";

    private static final String COLUMN_NAMES = "id, client_id, client_id_issued_at, client_secret, "
            + "client_secret_expires_at, client_name, client_authentication_methods, authorization_grant_types, "
            + "redirect_uris, post_logout_redirect_uris, scopes, client_settings, token_settings";
    private static final String SELECT = "SELECT " + COLUMN_NAMES + " FROM oauth2_registered_client WHERE ";
    private static final String INSERT = "INSERT INTO oauth2_registered_client (" + COLUMN_NAMES
            + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String UPDATE = "UPDATE oauth2_registered_client SET client_secret = ?, "
            + "client_secret_expires_at = ?, client_name = ?, client_authentication_methods = ?, "
            + "authorization_grant_types = ?, redirect_uris = ?, post_logout_redirect_uris = ?, scopes = ?, "
            + "client_settings = ?, token_settings = ? WHERE id = ?";

    private final DataSource dataSource;
    private ObjectMapper objectMapper = new ObjectMapper();

    public JdbcRegisteredClientRepository(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource cannot be null");
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    public final void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper cannot be null");
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Objects.requireNonNull(registeredClient, "registeredClient cannot be null");
        inTransaction(connection -> {
            if (findBy(connection, "id = ?", registeredClient.getId()) == null) {
                assertUniqueIdentifiers(connection, registeredClient);
                insert(connection, registeredClient);
            } else {
                update(connection, registeredClient);
            }
            return null;
        }, "save registered client");
    }

    @Override
    public RegisteredClient findById(String id) {
        Arguments.requireNonBlank(id, "id");
        return withConnection(connection -> findBy(connection, "id = ?", id), "find registered client by id");
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Arguments.requireNonBlank(clientId, "clientId");
        return withConnection(connection -> findBy(connection, "client_id = ?", clientId),
                "find registered client by client id");
    }

    private void insert(Connection connection, RegisteredClient registeredClient) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT)) {
            statement.setString(1, registeredClient.getId());
            statement.setString(2, registeredClient.getClientId());
            setTimestamp(statement, 3, registeredClient.getClientIdIssuedAt() != null
                    ? registeredClient.getClientIdIssuedAt()
                    : Instant.now());
            statement.setString(4, registeredClient.getClientSecret());
            setTimestamp(statement, 5, registeredClient.getClientSecretExpiresAt());
            statement.setString(6, registeredClient.getClientName());
            statement.setString(7, join(registeredClient.getClientAuthenticationMethods(),
                    ClientAuthenticationMethod::getValue));
            statement.setString(8, join(registeredClient.getAuthorizationGrantTypes(),
                    AuthorizationGrantType::getValue));
            statement.setString(9, join(registeredClient.getRedirectUris(), Function.identity()));
            statement.setString(10, join(registeredClient.getPostLogoutRedirectUris(), Function.identity()));
            statement.setString(11, join(registeredClient.getScopes(), Function.identity()));
            statement.setString(12, writeMap(registeredClient.getClientSettings().getSettings()));
            statement.setString(13, writeMap(registeredClient.getTokenSettings().getSettings()));
            statement.executeUpdate();
        }
    }

    private static void assertUniqueIdentifiers(Connection connection, RegisteredClient registeredClient)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM oauth2_registered_client WHERE client_id = ?")) {
            statement.setString(1, registeredClient.getClientId());
            try (ResultSet resultSet = statement.executeQuery()) {
                resultSet.next();
                if (resultSet.getInt(1) > 0) {
                    throw new IllegalArgumentException(
                            "Registered client must be unique. Found duplicate client identifier: "
                                    + registeredClient.getClientId());
                }
            }
        }
    }

    private void update(Connection connection, RegisteredClient registeredClient) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPDATE)) {
            statement.setString(1, registeredClient.getClientSecret());
            setTimestamp(statement, 2, registeredClient.getClientSecretExpiresAt());
            statement.setString(3, registeredClient.getClientName());
            statement.setString(4, join(registeredClient.getClientAuthenticationMethods(),
                    ClientAuthenticationMethod::getValue));
            statement.setString(5, join(registeredClient.getAuthorizationGrantTypes(),
                    AuthorizationGrantType::getValue));
            statement.setString(6, join(registeredClient.getRedirectUris(), Function.identity()));
            statement.setString(7, join(registeredClient.getPostLogoutRedirectUris(), Function.identity()));
            statement.setString(8, join(registeredClient.getScopes(), Function.identity()));
            statement.setString(9, writeMap(registeredClient.getClientSettings().getSettings()));
            statement.setString(10, writeMap(registeredClient.getTokenSettings().getSettings()));
            statement.setString(11, registeredClient.getId());
            statement.executeUpdate();
        }
    }

    private RegisteredClient findBy(Connection connection, String filter, String value) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT + filter)) {
            statement.setString(1, value);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() ? mapRegisteredClient(resultSet) : null;
            }
        }
    }

    private RegisteredClient mapRegisteredClient(ResultSet resultSet) throws SQLException {
        RegisteredClient.Builder builder = RegisteredClient.withId(resultSet.getString("id"))
                .clientId(resultSet.getString("client_id"))
                .clientSecret(resultSet.getString("client_secret"))
                .clientName(resultSet.getString("client_name"));
        Timestamp clientIdIssuedAt = resultSet.getTimestamp("client_id_issued_at");
        if (clientIdIssuedAt != null) {
            builder.clientIdIssuedAt(clientIdIssuedAt.toInstant());
        }
        Timestamp clientSecretExpiresAt = resultSet.getTimestamp("client_secret_expires_at");
        if (clientSecretExpiresAt != null) {
            builder.clientSecretExpiresAt(clientSecretExpiresAt.toInstant());
        }
        split(resultSet.getString("client_authentication_methods")).stream()
                .map(ClientAuthenticationMethod::new)
                .forEach(builder::clientAuthenticationMethod);
        split(resultSet.getString("authorization_grant_types")).stream()
                .map(AuthorizationGrantType::new)
                .forEach(builder::authorizationGrantType);
        split(resultSet.getString("redirect_uris")).forEach(builder::redirectUri);
        split(resultSet.getString("post_logout_redirect_uris")).forEach(builder::postLogoutRedirectUri);
        split(resultSet.getString("scopes")).forEach(builder::scope);
        Map<String, Object> clientSettings = parseMap(resultSet.getString("client_settings"));
        if (!clientSettings.isEmpty()) {
            builder.clientSettings(ClientSettings.builder()
                    .settings(settings -> settings.putAll(clientSettings))
                    .build());
        }
        Map<String, Object> tokenSettings = parseMap(resultSet.getString("token_settings"));
        builder.tokenSettings(TokenSettings.builder()
                .settings(settings -> settings.putAll(tokenSettings))
                .build());
        return builder.build();
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<>() {
            });
        } catch (Exception exception) {
            throw new IllegalArgumentException(exception.getMessage(), exception);
        }
    }

    private String writeMap(Map<String, Object> data) {
        try {
            return this.objectMapper.writeValueAsString(data);
        } catch (Exception exception) {
            throw new IllegalArgumentException(exception.getMessage(), exception);
        }
    }

    private <T> T withConnection(SqlFunction<Connection, T> work, String operation) {
        try (Connection connection = this.dataSource.getConnection()) {
            return work.apply(connection);
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to " + operation, exception);
        }
    }

    private <T> T inTransaction(SqlFunction<Connection, T> work, String operation) {
        try (Connection connection = this.dataSource.getConnection()) {
            if (JdbcTransactionSupport.isEnlisted(this.dataSource)) {
                // The outer transaction owns completion, including the decision to roll back on failure.
                return work.apply(connection);
            }
            connection.setAutoCommit(false);
            try {
                T result = work.apply(connection);
                connection.commit();
                return result;
            } catch (Exception exception) {
                rollback(connection, exception);
                if (exception instanceof RuntimeException runtimeException) {
                    throw runtimeException;
                }
                throw new IllegalStateException("Unable to " + operation, exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to " + operation, exception);
        }
    }

    private static void rollback(Connection connection, Exception cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackException) {
            cause.addSuppressed(rollbackException);
        }
    }

    private static void setTimestamp(PreparedStatement statement, int index, Instant value) throws SQLException {
        if (value == null) {
            statement.setTimestamp(index, null);
        } else {
            statement.setTimestamp(index, Timestamp.from(value));
        }
    }

    private static <T> String join(Set<T> values, Function<T, String> mapper) {
        return values.stream().map(mapper).collect(Collectors.joining(","));
    }

    private static Set<String> split(String values) {
        if (values == null || values.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(values.split(",", -1))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @FunctionalInterface
    private interface SqlFunction<T, R> {
        R apply(T value) throws SQLException;
    }
}

package io.quarkiverse.authorization.server.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.sql.DataSource;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTransactionSupport;
import io.quarkiverse.authorization.server.runtime.util.Arguments;

/**
 * JDBC implementation of {@link OAuth2AuthorizationConsentService} using an application-provided {@link DataSource}.
 */
public final class JdbcOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    public static final String SCHEMA_LOCATION = "META-INF/quarkus-authorization-server/schema/oauth2-authorization-consent-schema.sql";

    private static final String SELECT = "SELECT registered_client_id, principal_name, authorities "
            + "FROM oauth2_authorization_consent WHERE registered_client_id = ? AND principal_name = ?";
    private static final String INSERT = "INSERT INTO oauth2_authorization_consent "
            + "(registered_client_id, principal_name, authorities) VALUES (?, ?, ?)";
    private static final String UPDATE = "UPDATE oauth2_authorization_consent SET authorities = ? "
            + "WHERE registered_client_id = ? AND principal_name = ?";
    private static final String DELETE = "DELETE FROM oauth2_authorization_consent "
            + "WHERE registered_client_id = ? AND principal_name = ?";

    private final DataSource dataSource;
    private final RegisteredClientRepository registeredClientRepository;

    public JdbcOAuth2AuthorizationConsentService(DataSource dataSource,
            RegisteredClientRepository registeredClientRepository) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource cannot be null");
        this.registeredClientRepository = Objects.requireNonNull(
                registeredClientRepository, "registeredClientRepository cannot be null");
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Objects.requireNonNull(authorizationConsent, "authorizationConsent cannot be null");
        inTransaction(connection -> {
            if (exists(connection, authorizationConsent.getRegisteredClientId(),
                    authorizationConsent.getPrincipalName())) {
                update(connection, authorizationConsent);
            } else {
                insert(connection, authorizationConsent);
            }
            return null;
        }, "save authorization consent");
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Objects.requireNonNull(authorizationConsent, "authorizationConsent cannot be null");
        inTransaction(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(DELETE)) {
                statement.setString(1, authorizationConsent.getRegisteredClientId());
                statement.setString(2, authorizationConsent.getPrincipalName());
                statement.executeUpdate();
            }
            return null;
        }, "remove authorization consent");
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Arguments.requireNonBlank(registeredClientId, "registeredClientId");
        Arguments.requireNonBlank(principalName, "principalName");
        ConsentRow row = withConnection(connection -> findRow(connection, registeredClientId, principalName),
                "find authorization consent");
        if (row == null) {
            return null;
        }
        if (this.registeredClientRepository.findById(row.registeredClientId()) == null) {
            throw new IllegalStateException("The registered client associated with the authorization consent was not found");
        }
        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
                row.registeredClientId(), row.principalName());
        split(row.authorities()).forEach(builder::authority);
        return builder.build();
    }

    private static void insert(Connection connection, OAuth2AuthorizationConsent authorizationConsent)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT)) {
            statement.setString(1, authorizationConsent.getRegisteredClientId());
            statement.setString(2, authorizationConsent.getPrincipalName());
            statement.setString(3, join(authorizationConsent.getAuthorities()));
            statement.executeUpdate();
        }
    }

    private static void update(Connection connection, OAuth2AuthorizationConsent authorizationConsent)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPDATE)) {
            statement.setString(1, join(authorizationConsent.getAuthorities()));
            statement.setString(2, authorizationConsent.getRegisteredClientId());
            statement.setString(3, authorizationConsent.getPrincipalName());
            statement.executeUpdate();
        }
    }

    private static boolean exists(Connection connection, String registeredClientId, String principalName)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM oauth2_authorization_consent "
                        + "WHERE registered_client_id = ? AND principal_name = ?")) {
            statement.setString(1, registeredClientId);
            statement.setString(2, principalName);
            try (ResultSet resultSet = statement.executeQuery()) {
                resultSet.next();
                return resultSet.getInt(1) > 0;
            }
        }
    }

    private static ConsentRow findRow(Connection connection, String registeredClientId, String principalName)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT)) {
            statement.setString(1, registeredClientId);
            statement.setString(2, principalName);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return null;
                }
                return new ConsentRow(
                        resultSet.getString("registered_client_id"),
                        resultSet.getString("principal_name"),
                        resultSet.getString("authorities"));
            }
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

    private static String join(Set<String> values) {
        return values.stream().sorted().collect(Collectors.joining(","));
    }

    private static Set<String> split(String values) {
        if (values == null || values.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(values.split(","))
                .filter(value -> !value.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @FunctionalInterface
    private interface SqlFunction<T, R> {

        R apply(T value) throws SQLException;
    }

    private record ConsentRow(String registeredClientId, String principalName, String authorities) {
    }
}

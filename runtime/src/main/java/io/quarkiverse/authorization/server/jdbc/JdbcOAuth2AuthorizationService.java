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
import java.util.stream.Collectors;

import javax.sql.DataSource;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationCode;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcTransactionSupport;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;

/**
 * JDBC implementation of {@link OAuth2AuthorizationService} using an application-provided {@link DataSource}.
 */
public final class JdbcOAuth2AuthorizationService implements OAuth2AuthorizationService {

    public static final String SCHEMA_LOCATION = "META-INF/quarkus-authorization-server/schema/oauth2-authorization-schema.sql";

    private static final String COLUMN_NAMES = "id, registered_client_id, principal_name, authorization_grant_type, authorized_scopes,"
            + " attributes, state, authorization_code_value, authorization_code_issued_at,"
            + " authorization_code_expires_at, authorization_code_metadata, access_token_value,"
            + " access_token_issued_at, access_token_expires_at, access_token_metadata,"
            + " access_token_type, access_token_scopes, oidc_id_token_value,"
            + " oidc_id_token_issued_at, oidc_id_token_expires_at, oidc_id_token_metadata,"
            + " refresh_token_value, refresh_token_issued_at, refresh_token_expires_at,"
            + " refresh_token_metadata, user_code_value, user_code_issued_at,"
            + " user_code_expires_at, user_code_metadata, device_code_value,"
            + " device_code_issued_at, device_code_expires_at, device_code_metadata";
    private static final String SELECT = "SELECT " + COLUMN_NAMES + " FROM oauth2_authorization WHERE ";
    private static final String INSERT = "INSERT INTO oauth2_authorization ("
            + COLUMN_NAMES
            + ") VALUES ("
            + placeholders(33)
            + ")";
    private static final String UPDATE = "UPDATE oauth2_authorization SET registered_client_id = ?, principal_name = ?,"
            + " authorization_grant_type = ?, authorized_scopes = ?, attributes = ?, state = ?,"
            + " authorization_code_value = ?, authorization_code_issued_at = ?,"
            + " authorization_code_expires_at = ?, authorization_code_metadata = ?,"
            + " access_token_value = ?, access_token_issued_at = ?, access_token_expires_at ="
            + " ?, access_token_metadata = ?, access_token_type = ?, access_token_scopes = ?,"
            + " oidc_id_token_value = ?, oidc_id_token_issued_at = ?, oidc_id_token_expires_at"
            + " = ?, oidc_id_token_metadata = ?, refresh_token_value = ?,"
            + " refresh_token_issued_at = ?, refresh_token_expires_at = ?,"
            + " refresh_token_metadata = ?, user_code_value = ?, user_code_issued_at = ?,"
            + " user_code_expires_at = ?, user_code_metadata = ?, device_code_value = ?,"
            + " device_code_issued_at = ?, device_code_expires_at = ?, device_code_metadata = ?"
            + " WHERE id = ?";
    private static final String DELETE = "DELETE FROM oauth2_authorization WHERE id = ?";

    private final DataSource dataSource;
    private final RegisteredClientRepository registeredClientRepository;
    private final JdbcJsonCodec jsonCodec;

    public JdbcOAuth2AuthorizationService(DataSource dataSource,
            RegisteredClientRepository registeredClientRepository) {
        this(dataSource, registeredClientRepository, new JdbcJsonCodec());
    }

    public JdbcOAuth2AuthorizationService(DataSource dataSource,
            RegisteredClientRepository registeredClientRepository, JdbcJsonCodec jsonCodec) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource cannot be null");
        this.registeredClientRepository = Objects.requireNonNull(
                registeredClientRepository, "registeredClientRepository cannot be null");
        this.jsonCodec = Objects.requireNonNull(jsonCodec, "jsonCodec cannot be null");
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Objects.requireNonNull(authorization, "authorization cannot be null");
        inTransaction(
                connection -> {
                    if (!existsById(connection, authorization.getId())) {
                        insert(connection, authorization);
                    } else {
                        update(connection, authorization);
                    }
                    return null;
                },
                "save authorization");
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Objects.requireNonNull(authorization, "authorization cannot be null");
        inTransaction(connection -> {
            try (PreparedStatement statement = connection.prepareStatement(DELETE)) {
                statement.setString(1, authorization.getId());
                statement.executeUpdate();
            }
            return null;
        }, "remove authorization");
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Arguments.requireNonBlank(id, "id");
        return findBy(
                "id = ?", statement -> statement.setString(1, id), "find authorization by id");
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Arguments.requireNonBlank(token, "token");
        if (tokenType == null) {
            return findBy(
                    "state = ? OR authorization_code_value = ? OR access_token_value = ? OR"
                            + " oidc_id_token_value = ? OR refresh_token_value = ? OR user_code_value ="
                            + " ? OR device_code_value = ?",
                    statement -> {
                        for (int index = 1; index <= 7; index++) {
                            statement.setString(index, token);
                        }
                    },
                    "find authorization by token");
        }
        String column = tokenColumn(tokenType);
        if (column == null) {
            return null;
        }
        return findBy(column + " = ?", statement -> statement.setString(1, token),
                "find authorization by token");
    }

    private void insert(Connection connection, OAuth2Authorization authorization) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(INSERT)) {
            bindAuthorization(statement, authorization, true);
            statement.executeUpdate();
        }
    }

    private void update(Connection connection, OAuth2Authorization authorization) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(UPDATE)) {
            int nextIndex = bindAuthorization(statement, authorization, false);
            statement.setString(nextIndex, authorization.getId());
            statement.executeUpdate();
        }
    }

    private int bindAuthorization(PreparedStatement statement, OAuth2Authorization authorization, boolean includeId)
            throws SQLException {
        int index = 1;
        if (includeId) {
            statement.setString(index++, authorization.getId());
        }
        statement.setString(index++, authorization.getRegisteredClientId());
        statement.setString(index++, authorization.getPrincipalName());
        statement.setString(index++, authorization.getAuthorizationGrantType().getValue());
        statement.setString(index++, join(authorization.getAuthorizedScopes()));
        statement.setString(index++,
                this.jsonCodec.writeAuthorizationAttributes(authorization.getPrincipalName(), authorization.getAttributes()));
        Object state = authorization.getAttributes().get(OAuth2ParameterNames.STATE);
        statement.setString(index++, state instanceof String stringState ? stringState : null);

        index = bindToken(statement, index, authorization.getAuthorizationCode());
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        index = bindToken(statement, index, accessToken);
        statement.setString(index++, accessToken != null ? accessToken.getToken().getTokenType().getValue() : null);
        statement.setString(index++, accessToken != null ? join(accessToken.getToken().getScopes()) : null);

        index = bindToken(statement, index, authorization.getToken(OidcIdToken.class));
        index = bindToken(statement, index, authorization.getRefreshToken());
        index = bindToken(statement, index, authorization.getToken(OAuth2UserCode.class));
        return bindToken(statement, index, authorization.getToken(OAuth2DeviceCode.class));
    }

    private int bindToken(PreparedStatement statement, int index, OAuth2Authorization.Token<?> token) throws SQLException {
        if (token == null) {
            return bindEmptyToken(statement, index);
        }
        OAuth2Token oauth2Token = token.getToken();
        statement.setString(index++, oauth2Token.getTokenValue());
        setTimestamp(statement, index++, oauth2Token.getIssuedAt());
        setTimestamp(statement, index++, oauth2Token.getExpiresAt());
        statement.setString(index++, this.jsonCodec.writeTokenMetadata(token.getMetadata()));
        return index;
    }

    private static int bindEmptyToken(PreparedStatement statement, int index) throws SQLException {
        statement.setString(index++, null);
        setTimestamp(statement, index++, null);
        setTimestamp(statement, index++, null);
        statement.setString(index++, null);
        return index;
    }

    private static boolean existsById(Connection connection, String id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM oauth2_authorization WHERE id = ?")) {
            statement.setString(1, id);
            try (ResultSet resultSet = statement.executeQuery()) {
                resultSet.next();
                return resultSet.getInt(1) > 0;
            }
        }
    }

    private OAuth2Authorization findBy(String filter, StatementBinder binder, String operation) {
        AuthorizationRow row = withConnection(connection -> findRow(connection, filter, binder), operation);
        return row != null ? mapAuthorization(row) : null;
    }

    private static AuthorizationRow findRow(Connection connection, String filter, StatementBinder binder)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT + filter)) {
            binder.bind(statement);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return null;
                }
                return new AuthorizationRow(
                        resultSet.getString("id"),
                        resultSet.getString("registered_client_id"),
                        resultSet.getString("principal_name"),
                        resultSet.getString("authorization_grant_type"),
                        resultSet.getString("authorized_scopes"),
                        resultSet.getString("attributes"),
                        resultSet.getString("authorization_code_value"),
                        instant(resultSet, "authorization_code_issued_at"),
                        instant(resultSet, "authorization_code_expires_at"),
                        resultSet.getString("authorization_code_metadata"),
                        resultSet.getString("access_token_value"),
                        instant(resultSet, "access_token_issued_at"),
                        instant(resultSet, "access_token_expires_at"),
                        resultSet.getString("access_token_metadata"),
                        resultSet.getString("access_token_type"),
                        resultSet.getString("access_token_scopes"),
                        resultSet.getString("oidc_id_token_value"),
                        instant(resultSet, "oidc_id_token_issued_at"),
                        instant(resultSet, "oidc_id_token_expires_at"),
                        resultSet.getString("oidc_id_token_metadata"),
                        resultSet.getString("refresh_token_value"),
                        instant(resultSet, "refresh_token_issued_at"),
                        instant(resultSet, "refresh_token_expires_at"),
                        resultSet.getString("refresh_token_metadata"),
                        resultSet.getString("user_code_value"),
                        instant(resultSet, "user_code_issued_at"),
                        instant(resultSet, "user_code_expires_at"),
                        resultSet.getString("user_code_metadata"),
                        resultSet.getString("device_code_value"),
                        instant(resultSet, "device_code_issued_at"),
                        instant(resultSet, "device_code_expires_at"),
                        resultSet.getString("device_code_metadata"));
            }
        }
    }

    private OAuth2Authorization mapAuthorization(AuthorizationRow row) {
        RegisteredClient registeredClient = this.registeredClientRepository.findById(row.registeredClientId());
        if (registeredClient == null) {
            throw new IllegalStateException(
                    "The registered client associated with the authorization was not found");
        }
        Map<String, Object> attributes = this.jsonCodec.readAuthorizationAttributes(row.principalName(), row.attributes());
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(row.id())
                .principalName(row.principalName())
                .authorizationGrantType(new AuthorizationGrantType(row.authorizationGrantType()))
                .authorizedScopes(split(row.authorizedScopes()))
                .attributes(values -> values.putAll(attributes));

        String authorizationCodeValue = row.authorizationCodeValue();
        if (authorizationCodeValue != null && !authorizationCodeValue.isBlank()) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    authorizationCodeValue,
                    row.authorizationCodeIssuedAt(),
                    row.authorizationCodeExpiresAt());
            Map<String, Object> metadata = this.jsonCodec.readTokenMetadata(row.authorizationCodeMetadata());
            builder.token(authorizationCode, values -> values.putAll(metadata));
        }

        String accessTokenValue = row.accessTokenValue();
        if (accessTokenValue != null && !accessTokenValue.isBlank()) {
            String accessTokenType = row.accessTokenType();
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    accessTokenType != null ? new OAuth2AccessToken.TokenType(accessTokenType)
                            : OAuth2AccessToken.TokenType.BEARER,
                    accessTokenValue,
                    row.accessTokenIssuedAt(),
                    row.accessTokenExpiresAt(),
                    split(row.accessTokenScopes()));
            Map<String, Object> metadata = this.jsonCodec.readTokenMetadata(row.accessTokenMetadata());
            builder.token(accessToken, values -> values.putAll(metadata));
        }

        if (row.idTokenValue() != null && !row.idTokenValue().isBlank()) {
            Map<String, Object> metadata = this.jsonCodec.readTokenMetadata(row.idTokenMetadata());
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = (Map<String, Object>) metadata.get(
                    OAuth2Authorization.Token.CLAIMS_METADATA_NAME);
            OidcIdToken idToken = new OidcIdToken(row.idTokenValue(), row.idTokenIssuedAt(),
                    row.idTokenExpiresAt(), claims);
            builder.token(idToken, values -> values.putAll(metadata));
        }

        String refreshTokenValue = row.refreshTokenValue();
        if (refreshTokenValue != null && !refreshTokenValue.isBlank()) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    refreshTokenValue,
                    row.refreshTokenIssuedAt(),
                    row.refreshTokenExpiresAt());
            Map<String, Object> metadata = this.jsonCodec.readTokenMetadata(row.refreshTokenMetadata());
            builder.token(refreshToken, values -> values.putAll(metadata));
        }

        String userCodeValue = row.userCodeValue();
        if (userCodeValue != null && !userCodeValue.isBlank()) {
            OAuth2UserCode userCode = new OAuth2UserCode(
                    userCodeValue, row.userCodeIssuedAt(), row.userCodeExpiresAt());
            Map<String, Object> metadata = this.jsonCodec.readTokenMetadata(row.userCodeMetadata());
            builder.token(userCode, values -> values.putAll(metadata));
        }

        String deviceCodeValue = row.deviceCodeValue();
        if (deviceCodeValue != null && !deviceCodeValue.isBlank()) {
            OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
                    deviceCodeValue, row.deviceCodeIssuedAt(), row.deviceCodeExpiresAt());
            Map<String, Object> metadata = this.jsonCodec.readTokenMetadata(row.deviceCodeMetadata());
            builder.token(deviceCode, values -> values.putAll(metadata));
        }
        return builder.build();
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

    private static String tokenColumn(OAuth2TokenType tokenType) {
        if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            return "oidc_id_token_value";
        }
        if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return "access_token_value";
        }
        if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return "refresh_token_value";
        }
        if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return "state";
        }
        if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return "authorization_code_value";
        }
        if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            return "user_code_value";
        }
        if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            return "device_code_value";
        }
        return null;
    }

    private static Instant instant(ResultSet resultSet, String column) throws SQLException {
        Timestamp timestamp = resultSet.getTimestamp(column);
        return timestamp != null ? timestamp.toInstant() : null;
    }

    private static void setTimestamp(PreparedStatement statement, int index, Instant value) throws SQLException {
        statement.setTimestamp(index, value != null ? Timestamp.from(value) : null);
    }

    private static String join(Set<String> values) {
        return values == null || values.isEmpty() ? null : String.join(",", values);
    }

    private static Set<String> split(String values) {
        if (values == null || values.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(values.split(",", -1))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static String placeholders(int count) {
        return java.util.stream.IntStream.range(0, count)
                .mapToObj(index -> "?")
                .collect(Collectors.joining(", "));
    }

    @FunctionalInterface
    private interface SqlFunction<T, R> {
        R apply(T value) throws SQLException;
    }

    @FunctionalInterface
    private interface StatementBinder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    private record AuthorizationRow(
            String id,
            String registeredClientId,
            String principalName,
            String authorizationGrantType,
            String authorizedScopes,
            String attributes,
            String authorizationCodeValue,
            Instant authorizationCodeIssuedAt,
            Instant authorizationCodeExpiresAt,
            String authorizationCodeMetadata,
            String accessTokenValue,
            Instant accessTokenIssuedAt,
            Instant accessTokenExpiresAt,
            String accessTokenMetadata,
            String accessTokenType,
            String accessTokenScopes,
            String idTokenValue,
            Instant idTokenIssuedAt,
            Instant idTokenExpiresAt,
            String idTokenMetadata,
            String refreshTokenValue,
            Instant refreshTokenIssuedAt,
            Instant refreshTokenExpiresAt,
            String refreshTokenMetadata,
            String userCodeValue,
            Instant userCodeIssuedAt,
            Instant userCodeExpiresAt,
            String userCodeMetadata,
            String deviceCodeValue,
            Instant deviceCodeIssuedAt,
            Instant deviceCodeExpiresAt,
            String deviceCodeMetadata) {
    }
}

package io.quarkiverse.authorization.server.runtime.jdbc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.UUID;

import javax.sql.DataSource;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;

class JdbcLocalTransactionTest {

    @Test
    void plainJdbcTestsRunWithoutAgroalOrJta() {
        ClassLoader classLoader = JdbcLocalTransactionTest.class.getClassLoader();
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName("io.agroal.api.AgroalDataSource", false, classLoader));
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName("io.quarkus.narayana.jta.QuarkusTransaction", false, classLoader));
    }

    @ParameterizedTest
    @EnumSource(Repository.class)
    void rollsBackAnExecutedWriteWhenTheJdbcCallFails(Repository repository) throws SQLException {
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1");
        JdbcTestSupport.executeSchema(dataSource, JdbcRegisteredClientRepository.SCHEMA_LOCATION);
        JdbcTestSupport.executeSchema(dataSource, JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
        JdbcTestSupport.executeSchema(dataSource, JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION);
        DataSource failing = failAfterWrite(DataSource.class, dataSource);
        var clients = new JdbcRegisteredClientRepository(failing);
        var client = RegisteredClient.withId("client").clientId("client")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();

        var failure = assertThrows(IllegalStateException.class, () -> {
            switch (repository) {
                case CLIENT -> clients.save(client);
                case AUTHORIZATION -> new JdbcOAuth2AuthorizationService(failing, clients)
                        .save(OAuth2Authorization.withRegisteredClient(client).principalName("subject")
                                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build());
                case CONSENT -> new JdbcOAuth2AuthorizationConsentService(failing, clients)
                        .save(OAuth2AuthorizationConsent.withId(client.getId(), "subject").scope("read").build());
            }
        });
        var sqlFailure = assertInstanceOf(SQLException.class, failure.getCause());
        assertEquals("Failure after the database executed the write", sqlFailure.getMessage());

        // The INSERT really ran; a new connection must see that the repository rolled it back.
        try (var connection = dataSource.getConnection();
                var statement = connection.createStatement();
                var rows = statement.executeQuery("SELECT COUNT(*) FROM " + repository.table)) {
            assertTrue(rows.next());
            assertEquals(0, rows.getInt(1));
        }
    }

    private static <T> T failAfterWrite(Class<T> type, T delegate) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (proxy, method, args) -> {
            Object result;
            try {
                result = method.invoke(delegate, args);
            } catch (InvocationTargetException exception) {
                throw exception.getCause();
            }
            if (method.getName().equals("executeUpdate")) {
                throw new SQLException("Failure after the database executed the write");
            }
            if (result instanceof Connection connection) {
                return failAfterWrite(Connection.class, connection);
            }
            if (result instanceof PreparedStatement statement) {
                return failAfterWrite(PreparedStatement.class, statement);
            }
            return result;
        }));
    }

    enum Repository {
        CLIENT("oauth2_registered_client"),
        AUTHORIZATION("oauth2_authorization"),
        CONSENT("oauth2_authorization_consent");

        private final String table;

        Repository(String table) {
            this.table = table;
        }
    }
}

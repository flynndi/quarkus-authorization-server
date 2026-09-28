package io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.SQLException;
import java.util.Set;
import java.util.UUID;

import javax.sql.DataSource;

import jakarta.inject.Inject;
import jakarta.transaction.RollbackException;
import jakarta.transaction.Status;
import jakarta.transaction.TransactionSynchronizationRegistry;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.agroal.api.AgroalDataSource;
import io.agroal.api.configuration.supplier.AgroalDataSourceConfigurationSupplier;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsent;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.narayana.jta.QuarkusTransactionException;
import io.quarkus.test.junit.QuarkusTest;

/** Real H2/Agroal/Narayana persistence checks; no default HTTP grant transaction is installed by this fixture. */
@QuarkusTest
class JdbcTransactionTest {

    @Inject
    DataSource dataSource;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    OAuth2AuthorizationConsentService consents;
    @Inject
    TransactionSynchronizationRegistry transactions;

    @Test
    void commitsAllRepositoriesOnlyWhenTheOuterTransactionCompletes() {
        Stores stores = managedStores();
        Rows rows = rows();

        QuarkusTransaction.joiningExisting().run(() -> {
            Object transaction = this.transactions.getTransactionKey();
            assertNotNull(transaction);
            stores.save(rows);
            stores.assertPresent(rows);
            assertSame(transaction, this.transactions.getTransactionKey());
            assertEquals(Status.STATUS_ACTIVE, this.transactions.getTransactionStatus());

            // Another connection must not observe any of the writes before the application's commit.
            QuarkusTransaction.suspendingExisting().run(() -> stores.assertAbsent(rows));
        });

        assertNull(this.transactions.getTransactionKey());
        stores.assertPresent(rows);
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void rollsBackAllRepositoriesOnALaterApplicationFailure(boolean wrappedDataSource) {
        Stores stores = wrappedDataSource ? stores(wrap(this.dataSource)) : managedStores();
        Rows rows = rows();
        IllegalStateException failure = new IllegalStateException("Application failed after persistence");

        assertSame(failure, assertThrows(IllegalStateException.class,
                () -> QuarkusTransaction.joiningExisting().run(() -> {
                    stores.save(rows);
                    stores.assertPresent(rows);
                    throw failure;
                })));

        stores.assertAbsent(rows);
    }

    @Test
    void rollsBackEarlierRepositoriesWhenALaterSqlStatementFails() {
        Stores stores = managedStores();
        Rows rows = rows();
        OAuth2AuthorizationConsent tooLarge = OAuth2AuthorizationConsent.from(rows.consent())
                .authority("x".repeat(1001)).build();

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> QuarkusTransaction.joiningExisting().run(() -> {
                    stores.clients().save(rows.client());
                    stores.authorizations().save(rows.authorization());
                    stores.consents().save(tooLarge);
                }));

        assertInstanceOf(SQLException.class, failure.getCause());
        stores.assertAbsent(rows);
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void updatesParticipateInTheOuterCommitOrRollback(boolean rollback) {
        Stores stores = managedStores();
        Rows original = rows();
        stores.save(original);
        Rows updated = new Rows(
                RegisteredClient.from(original.client()).clientName("Updated client").build(),
                OAuth2Authorization.from(original.authorization()).authorizedScopes(Set.of("write")).build(),
                OAuth2AuthorizationConsent.withId(original.client().getId(), "subject").scope("write").build());

        complete(rollback, () -> {
            stores.save(updated);
            stores.assertPresent(updated);
        });

        stores.assertPresent(rollback ? original : updated);
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    void removalsParticipateInTheOuterCommitOrRollback(boolean rollback) {
        Stores stores = managedStores();
        Rows rows = rows();
        stores.save(rows);

        complete(rollback, () -> {
            stores.authorizations().remove(rows.authorization());
            stores.consents().remove(rows.consent());
            assertNull(stores.authorizations().findById(rows.authorization().getId()));
            assertNull(stores.consents().findById(rows.client().getId(), "subject"));
        });

        assertNotNull(stores.clients().findById(rows.client().getId()));
        if (rollback) {
            stores.assertPresent(rows);
        } else {
            assertNull(stores.authorizations().findById(rows.authorization().getId()));
            assertNull(stores.consents().findById(rows.client().getId(), "subject"));
        }
    }

    @Test
    void savesWithoutAnOuterTransaction() {
        assertNull(this.transactions.getTransactionKey());
        Stores stores = managedStores();
        Rows rows = rows();
        stores.save(rows);
        assertNull(this.transactions.getTransactionKey());
        stores.assertPresent(rows);
    }

    @Test
    void plainDataSourceRemainsIndependentOfAnAmbientJtaTransaction() throws SQLException {
        JdbcDataSource plain = new JdbcDataSource();
        plain.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1");
        assertIndependentLocalTransactions(plain);
    }

    @Test
    void agroalWithoutTransactionIntegrationRemainsIndependentOfAnAmbientJtaTransaction() throws SQLException {
        try (AgroalDataSource local = AgroalDataSource.from(new AgroalDataSourceConfigurationSupplier()
                .connectionPoolConfiguration(pool -> pool.maxSize(4)
                        .connectionFactoryConfiguration(factory -> factory
                                .jdbcUrl("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1")
                                .connectionProviderClass(org.h2.Driver.class))))) {
            assertIndependentLocalTransactions(local);
        }
    }

    private void complete(boolean rollback, Runnable work) {
        Runnable transaction = () -> QuarkusTransaction.joiningExisting().run(() -> {
            work.run();
            if (rollback) {
                this.transactions.setRollbackOnly();
            }
        });
        if (rollback) {
            var failure = assertThrows(QuarkusTransactionException.class, transaction::run);
            assertInstanceOf(RollbackException.class, failure.getCause());
        } else {
            transaction.run();
        }
    }

    private void assertIndependentLocalTransactions(DataSource local) throws SQLException {
        try (var connection = local.getConnection(); var statement = connection.createStatement()) {
            for (String schema : Set.of(JdbcRegisteredClientRepository.SCHEMA_LOCATION,
                    JdbcOAuth2AuthorizationService.SCHEMA_LOCATION,
                    JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION)) {
                statement.execute("RUNSCRIPT FROM 'classpath:" + schema + "'");
            }
        }
        Stores stores = stores(local);
        Rows rows = rows();
        IllegalStateException failure = new IllegalStateException("Unrelated JTA transaction failed");
        assertSame(failure, assertThrows(IllegalStateException.class,
                () -> QuarkusTransaction.joiningExisting().run(() -> {
                    // Enlist the managed datasource too, so a global transaction-presence check would be wrong.
                    this.clients.findById(AuthorizationServerPersistence.PUBLIC_CLIENT_REGISTRATION_ID);
                    stores.save(rows);
                    throw failure;
                })));
        stores.assertPresent(rows);
    }

    private Stores managedStores() {
        assertInstanceOf(JdbcRegisteredClientRepository.class, this.clients);
        assertInstanceOf(JdbcOAuth2AuthorizationService.class, this.authorizations);
        assertInstanceOf(JdbcOAuth2AuthorizationConsentService.class, this.consents);
        return new Stores(this.clients, this.authorizations, this.consents);
    }

    private static Stores stores(DataSource dataSource) {
        var clients = new JdbcRegisteredClientRepository(dataSource);
        return new Stores(clients, new JdbcOAuth2AuthorizationService(dataSource, clients),
                new JdbcOAuth2AuthorizationConsentService(dataSource, clients));
    }

    private static Rows rows() {
        String id = UUID.randomUUID().toString();
        RegisteredClient client = RegisteredClient.withId(id).clientId(id).clientName("Original client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("read").scope("write").build();
        return new Rows(client, OAuth2Authorization.withRegisteredClient(client).id(id).principalName("subject")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).authorizedScopes(Set.of("read")).build(),
                OAuth2AuthorizationConsent.withId(id, "subject").scope("read").build());
    }

    private static DataSource wrap(DataSource delegate) {
        // Preserve the JDBC Wrapper contract while hiding the concrete Agroal type.
        return (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(), new Class<?>[] { DataSource.class },
                (proxy, method, args) -> {
                    try {
                        return method.invoke(delegate, args);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                });
    }

    private record Rows(RegisteredClient client, OAuth2Authorization authorization, OAuth2AuthorizationConsent consent) {
    }

    private record Stores(RegisteredClientRepository clients, OAuth2AuthorizationService authorizations,
            OAuth2AuthorizationConsentService consents) {

        void save(Rows rows) {
            this.clients.save(rows.client());
            this.authorizations.save(rows.authorization());
            this.consents.save(rows.consent());
        }

        void assertPresent(Rows rows) {
            var client = this.clients.findById(rows.client().getId());
            assertNotNull(client);
            assertEquals(rows.client().getClientName(), client.getClientName());
            var authorization = this.authorizations.findById(rows.authorization().getId());
            assertNotNull(authorization);
            assertEquals(rows.authorization().getAuthorizedScopes(), authorization.getAuthorizedScopes());
            var consent = this.consents.findById(rows.client().getId(), "subject");
            assertNotNull(consent);
            assertEquals(rows.consent().getAuthorities(), consent.getAuthorities());
        }

        void assertAbsent(Rows rows) {
            assertNull(this.clients.findById(rows.client().getId()));
            assertNull(this.authorizations.findById(rows.authorization().getId()));
            assertNull(this.consents.findById(rows.client().getId(), "subject"));
        }
    }
}

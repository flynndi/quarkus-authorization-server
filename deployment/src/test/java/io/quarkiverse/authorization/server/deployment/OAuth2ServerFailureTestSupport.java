package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.test.InMemoryLogHandler;
import io.restassured.response.Response;

final class OAuth2ServerFailureTestSupport {

    static final String SENSITIVE_DESCRIPTION = "Storage unavailable: db-password=internal-secret";
    static final String SENSITIVE_URI = "https://private-db.example.com/debug";
    static final String SQL_FAILURE = "Connection failed: jdbc:postgresql://private-db/accounts";

    private OAuth2ServerFailureTestSupport() {
    }

    static Response assertServerFailureLogged(Supplier<Response> request) {
        var logger = Logger.getLogger("");
        var logs = new InMemoryLogHandler(record -> record.getThrown() != null);
        logger.addHandler(logs);
        try {
            Response response = request.get();
            assertTrue(logs.getRecords().stream().anyMatch(OAuth2ServerFailureTestSupport::retainsSqlFailure),
                    "Server failures must be logged at ERROR with the original SQL cause");
            return response;
        } finally {
            logger.removeHandler(logs);
            logs.close();
        }
    }

    private static boolean retainsSqlFailure(LogRecord record) {
        if (record.getLevel().intValue() < Level.SEVERE.intValue()) {
            return false;
        }
        for (Throwable failure = record.getThrown(); failure != null; failure = failure.getCause()) {
            if (failure instanceof SQLException && SQL_FAILURE.equals(failure.getMessage())) {
                return true;
            }
        }
        return false;
    }

    @Singleton
    public static class Authorizations implements OAuth2AuthorizationService {
        private final InMemoryOAuth2AuthorizationService delegate = new InMemoryOAuth2AuthorizationService();
        private volatile String failingOperation;
        private volatile RuntimeException failure;

        void failOn(String operation, boolean classified) {
            this.failingOperation = operation;
            var cause = new SQLException(SQL_FAILURE);
            this.failure = classified
                    ? new OAuth2AuthenticationException(
                            new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, SENSITIVE_DESCRIPTION, SENSITIVE_URI), cause)
                    : new IllegalStateException("Storage operation failed", cause);
        }

        void clearFailure() {
            this.failure = null;
        }

        private void failIfRequested(String operation) {
            RuntimeException configuredFailure = this.failure;
            if (configuredFailure != null && operation.equals(this.failingOperation)) {
                throw configuredFailure;
            }
        }

        @Override
        public void save(OAuth2Authorization authorization) {
            failIfRequested("save");
            this.delegate.save(authorization);
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
            this.delegate.remove(authorization);
        }

        @Override
        public OAuth2Authorization findById(String id) {
            failIfRequested("find");
            return this.delegate.findById(id);
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            failIfRequested("find");
            return this.delegate.findByToken(token, tokenType);
        }
    }
}

package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class DuplicateAuthorizationGrantHandlerTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(
                    jar -> jar.addClasses(
                            FirstGrantHandler.class, SecondGrantHandler.class))
            .assertException(
                    throwable -> {
                        assertTrue(
                                hasMessage(
                                        throwable,
                                        "Duplicate OAuth2 authorization grant handlers for"
                                                + " grant_type 'urn:test:duplicate'"),
                                throwable.toString());
                        assertTrue(
                                hasMessage(throwable, FirstGrantHandler.class.getName()),
                                throwable.toString());
                        assertTrue(
                                hasMessage(throwable, SecondGrantHandler.class.getName()),
                                throwable.toString());
                    });

    @Test
    void rejectsTwoCustomHandlersWithEqualGrantTypeValuesAtStartup() {
    }

    private static boolean hasMessage(Throwable throwable, String message) {
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current.getMessage() != null && current.getMessage().contains(message)) {
                return true;
            }
        }
        return false;
    }

    @Singleton
    public static class FirstGrantHandler implements TokenGrantHandler {

        @Override
        public AuthorizationGrantType getGrantType() {
            return new AuthorizationGrantType("urn:test:duplicate");
        }

        @Override
        public Uni<TokenIssuanceResult> handle(RoutingContext context) {
            throw new AssertionError("The application must fail before processing requests");
        }
    }

    @Singleton
    public static class SecondGrantHandler extends FirstGrantHandler {
    }
}

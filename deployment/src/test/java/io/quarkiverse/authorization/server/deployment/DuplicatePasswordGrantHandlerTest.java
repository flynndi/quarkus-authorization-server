package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordGrantHandler;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class DuplicatePasswordGrantHandlerTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClass(CustomPasswordGrantHandler.class))
            .assertException(
                    throwable -> {
                        assertTrue(
                                hasMessage(
                                        throwable,
                                        "Duplicate OAuth2 authorization grant handlers for"
                                                + " grant_type 'password'"),
                                throwable.toString());
                        assertTrue(
                                hasMessage(throwable, PasswordGrantHandler.class.getName()),
                                throwable.toString());
                        assertTrue(
                                hasMessage(
                                        throwable,
                                        CustomPasswordGrantHandler.class.getName()),
                                throwable.toString());
                    });

    @Test
    void rejectsHandlerThatShadowsTheBuiltInPasswordGrantAtStartup() {
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
    public static class CustomPasswordGrantHandler implements TokenGrantHandler {

        @Override
        public AuthorizationGrantType getGrantType() {
            return new AuthorizationGrantType("password");
        }

        @Override
        public Uni<TokenIssuanceResult> handle(RoutingContext context) {
            throw new AssertionError("The application must fail before processing requests");
        }
    }
}

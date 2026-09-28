package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationConsentPolicy;
import io.quarkus.test.QuarkusUnitTest;

class ConflictingConsentPoliciesTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClass(ConflictingValidators.class))
            .assertException(
                    failure -> {
                        assertTrue(
                                hasMessage(failure, "Ambiguous dependencies"),
                                failure.toString());
                        assertTrue(
                                hasMessage(failure, "AuthorizationConsentPolicy"),
                                failure.toString());
                        assertTrue(
                                hasMessage(failure, "ConflictingValidators"),
                                failure.toString());
                        assertTrue(
                                hasMessage(failure, "firstValidator"), failure.toString());
                    });

    @Test
    void rejectsTwoIndependentSingleValuePoliciesBeforeRequests() {
    }

    private static boolean hasMessage(Throwable failure, String message) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current.getMessage() != null && current.getMessage().contains(message)) {
                return true;
            }
        }
        return false;
    }

    @Singleton
    public static class ConflictingValidators {
        @Produces
        @Singleton
        AuthorizationConsentPolicy firstValidator() {
            return context -> false;
        }

        @Produces
        @Singleton
        AuthorizationConsentPolicy secondValidator() {
            return context -> false;
        }
    }
}

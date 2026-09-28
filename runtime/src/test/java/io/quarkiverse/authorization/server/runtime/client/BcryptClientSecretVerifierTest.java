package io.quarkiverse.authorization.server.runtime.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BcryptClientSecretVerifierTest {

    private static final String CLIENT_SECRET_HASH = "$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK";

    private final BcryptClientSecretVerifier verifier = new BcryptClientSecretVerifier();

    @Test
    void matchesBcryptClientSecret() {
        assertTrue(this.verifier.matches("client-secret", CLIENT_SECRET_HASH));
        assertFalse(this.verifier.matches("wrong-secret", CLIENT_SECRET_HASH));
    }

    @Test
    void rejectsMissingOrUnsupportedCredentials() {
        assertFalse(this.verifier.matches(null, CLIENT_SECRET_HASH));
        assertFalse(this.verifier.matches("", CLIENT_SECRET_HASH));
        assertFalse(this.verifier.matches("client-secret", null));
        assertFalse(this.verifier.matches("client-secret", ""));
        assertFalse(this.verifier.matches("client-secret", "{noop}client-secret"));
        assertFalse(this.verifier.matches("client-secret", "$2z$invalid"));
    }
}

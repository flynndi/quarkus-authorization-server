package io.quarkiverse.authorization.server.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class OAuth2ErrorTest {

    @Test
    void createsErrorWithCodeOnly() {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
        assertNull(error.getDescription());
        assertNull(error.getUri());
        assertEquals("[invalid_request] ", error.toString());
    }

    @Test
    void createsErrorWithDescriptionAndUri() {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Client authentication failed",
                "https://example.com/errors/invalid-client");

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getErrorCode());
        assertEquals("Client authentication failed", error.getDescription());
        assertEquals("https://example.com/errors/invalid-client", error.getUri());
        assertEquals("[invalid_client] Client authentication failed", error.toString());
    }

    @Test
    void rejectsEmptyErrorCode() {
        assertThrows(IllegalArgumentException.class, () -> new OAuth2Error(null));
        assertThrows(IllegalArgumentException.class, () -> new OAuth2Error(""));
        assertThrows(IllegalArgumentException.class, () -> new OAuth2Error(" "));
    }
}

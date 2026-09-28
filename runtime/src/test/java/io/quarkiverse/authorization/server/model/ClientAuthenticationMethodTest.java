package io.quarkiverse.authorization.server.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ClientAuthenticationMethodTest {

    @Test
    void exposesValueAndUsesValueEquality() {
        ClientAuthenticationMethod authenticationMethod = new ClientAuthenticationMethod("client_secret_basic");

        assertEquals("client_secret_basic", authenticationMethod.getValue());
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authenticationMethod);
        assertEquals(authenticationMethod.getValue().hashCode(), authenticationMethod.hashCode());
        assertEquals("client_secret_basic", authenticationMethod.toString());
        assertNotEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, authenticationMethod);
    }

    @Test
    void rejectsEmptyValue() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAuthenticationMethod(null));
        assertThrows(IllegalArgumentException.class, () -> new ClientAuthenticationMethod(""));
        assertThrows(IllegalArgumentException.class, () -> new ClientAuthenticationMethod(" "));
    }
}

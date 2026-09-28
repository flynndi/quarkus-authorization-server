package io.quarkiverse.authorization.server.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class AuthorizationGrantTypeTest {

    @Test
    void exposesValueAndUsesValueEquality() {
        AuthorizationGrantType grantType = new AuthorizationGrantType("password");

        assertEquals("password", grantType.getValue());
        assertEquals(AuthorizationGrantType.PASSWORD, grantType);
        assertEquals(grantType.getValue().hashCode(), grantType.hashCode());
        assertNotEquals(AuthorizationGrantType.AUTHORIZATION_CODE, grantType);
        assertEquals("urn:ietf:params:oauth:grant-type:device_code",
                AuthorizationGrantType.DEVICE_CODE.getValue());
        assertEquals("urn:ietf:params:oauth:grant-type:token-exchange",
                AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
    }

    @Test
    void rejectsEmptyValue() {
        assertThrows(IllegalArgumentException.class, () -> new AuthorizationGrantType(null));
        assertThrows(IllegalArgumentException.class, () -> new AuthorizationGrantType(""));
        assertThrows(IllegalArgumentException.class, () -> new AuthorizationGrantType(" "));
    }
}

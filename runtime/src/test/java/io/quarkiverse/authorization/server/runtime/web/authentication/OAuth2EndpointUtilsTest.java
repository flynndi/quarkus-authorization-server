package io.quarkiverse.authorization.server.runtime.web.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;

class OAuth2EndpointUtilsTest {

    @Test
    void validatesAndNormalizesDeviceUserCode() {
        assertTrue(OAuth2EndpointUtils.validateUserCode("bcdf ghjk"));
        assertEquals("BCDF-GHJK", OAuth2EndpointUtils.normalizeUserCode("bcdf ghjk"));
        assertFalse(OAuth2EndpointUtils.validateUserCode("short"));
        assertThrows(
                IllegalArgumentException.class,
                () -> OAuth2EndpointUtils.normalizeUserCode("short"));
    }

    @Test
    void createsProtocolError() {
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> OAuth2EndpointUtils.throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "code",
                        OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Parameter: code", exception.getError().getDescription());
        assertEquals(OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI,
                exception.getError().getUri());
    }

}

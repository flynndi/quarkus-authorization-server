package io.quarkiverse.authorization.server.grant.devicecode;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

import org.junit.jupiter.api.Test;

import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class DeviceAuthorizationRequestTest {
    @Test
    void copiesProtocolParametersAndScopes() {
        var principal = QuarkusSecurityIdentity.builder().setAnonymous(true).build();
        var scopes = new LinkedHashSet<>(Set.of("read"));
        var parameters = new LinkedHashMap<String, Object>(Map.of("probe", "value"));
        var request = new DeviceAuthorizationRequest(principal, scopes, parameters);
        scopes.clear();
        parameters.clear();
        assertSame(principal, request.getClientPrincipal());
        assertEquals(Set.of("read"), request.getScopes());
        assertEquals(Map.of("probe", "value"), request.getAdditionalParameters());
        assertThrows(UnsupportedOperationException.class, () -> request.getScopes().clear());
        assertThrows(
                UnsupportedOperationException.class,
                () -> request.getAdditionalParameters().clear());
        assertThrows(
                NullPointerException.class,
                () -> new DeviceAuthorizationRequest(null, Set.of(), Map.of()));
    }
}

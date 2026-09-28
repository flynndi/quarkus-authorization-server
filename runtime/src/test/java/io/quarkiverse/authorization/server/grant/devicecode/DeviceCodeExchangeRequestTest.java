package io.quarkiverse.authorization.server.grant.devicecode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class DeviceCodeExchangeRequestTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("device-client"))
            .build();

    @Test
    void exposesDeviceCodeGrantParameters() {
        DeviceCodeExchangeRequest authentication = new DeviceCodeExchangeRequest(
                "device-code", CLIENT_PRINCIPAL, Map.of("resource", "messages"));

        assertEquals(AuthorizationGrantType.DEVICE_CODE, authentication.getGrantType());
        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals("device-code", authentication.getDeviceCode());
        assertEquals(Map.of("resource", "messages"), authentication.getAdditionalParameters());
    }

    @Test
    void copiesAdditionalParametersAndAcceptsNull() {
        Map<String, Object> additionalParameters = new HashMap<>(Map.of("resource", "messages"));
        DeviceCodeExchangeRequest authentication = new DeviceCodeExchangeRequest(
                "device-code", CLIENT_PRINCIPAL, additionalParameters);
        additionalParameters.put("resource", "changed");

        assertEquals(Map.of("resource", "messages"), authentication.getAdditionalParameters());
        assertEquals(
                Map.of(),
                new DeviceCodeExchangeRequest("device-code", CLIENT_PRINCIPAL, null)
                        .getAdditionalParameters());
    }

    @Test
    void rejectsMissingDeviceCodeOrClientPrincipal() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new DeviceCodeExchangeRequest(" ", CLIENT_PRINCIPAL, Map.of()));
        assertThrows(
                NullPointerException.class,
                () -> new DeviceCodeExchangeRequest("device-code", null, Map.of()));
    }
}

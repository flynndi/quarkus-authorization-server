package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.devicecode.DeviceCodeExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;

class DeviceCodeExchangeRequestParserTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("device-client"))
            .build();
    private final DeviceCodeExchangeRequestParser converter = new DeviceCodeExchangeRequestParser();

    @Test
    void convertsDeviceCodeGrantRequest() {
        MultiMap parameters = validParameters()
                .add("client_id", "device-client")
                .add("resource", "messages")
                .add("audience", "one")
                .add("audience", "two");

        DeviceCodeExchangeRequest authentication = this.converter.parse(context(parameters));

        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals("device-code", authentication.getDeviceCode());
        assertEquals(AuthorizationGrantType.DEVICE_CODE, authentication.getGrantType());
        assertEquals("messages", authentication.getAdditionalParameters().get("resource"));
        assertArrayEquals(
                new String[] { "one", "two" },
                (String[]) authentication.getAdditionalParameters().get("audience"));
        assertFalse(authentication.getAdditionalParameters().containsKey("client_id"));
    }

    @Test
    void returnsNullForAnotherGrantType() {
        assertNull(this.converter.parse(context(validParameters().set("grant_type", "password"))));
    }

    @Test
    void rejectsMissingRepeatedAndBlankDeviceCode() {
        assertInvalidDeviceCode(validParameters().remove("device_code"));
        assertInvalidDeviceCode(validParameters().add("device_code", "another"));
        assertInvalidDeviceCode(validParameters().set("device_code", " "));
    }

    @Test
    void requiresAuthenticatedClientPrincipal() {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(validParameters(), null)));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
    }

    private void assertInvalidDeviceCode(MultiMap parameters) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(parameters)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Parameter: device_code", exception.getError().getDescription());
    }

    private static MultiMap validParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add("grant_type", AuthorizationGrantType.DEVICE_CODE.getValue())
                .add("device_code", "device-code");
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, new QuarkusHttpUser(CLIENT_PRINCIPAL));
    }

    private static RoutingContext context(MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                DeviceCodeExchangeRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                DeviceCodeExchangeRequestParserTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, arguments) -> {
                    if ("request".equals(method.getName())) {
                        return request;
                    }
                    if ("user".equals(method.getName())) {
                        return user;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
    }
}

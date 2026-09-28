package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.devicecode.DeviceAuthorizationRequest;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

class DeviceAuthorizationRequestParserTest {

    private final DeviceAuthorizationRequestParser converter = new DeviceAuthorizationRequestParser();

    @Test
    void convertsScopeAndAdditionalParameters() {
        SecurityIdentity principal = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("device-client"))
                .build();
        MultiMap parameters = MultiMap.caseInsensitiveMultiMap()
                .add("client_id", "device-client")
                .add("scope", "message.read message.write")
                .add("audience", "messages");

        DeviceAuthorizationRequest authentication = this.converter.parse(context(principal, parameters));

        assertSame(principal, authentication.getClientPrincipal());
        assertEquals(Set.of("message.read", "message.write"), authentication.getScopes());
        assertEquals(Map.of("audience", "messages"), authentication.getAdditionalParameters());
    }

    @Test
    void rejectsRepeatedScopeAndMissingAuthenticatedClient() {
        MultiMap repeatedScope = MultiMap.caseInsensitiveMultiMap()
                .add("scope", "message.read")
                .add("scope", "message.write");
        OAuth2AuthenticationException invalidScope = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(identity(), repeatedScope)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, invalidScope.getError().getErrorCode());

        OAuth2AuthenticationException invalidClient = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(
                        context(null, MultiMap.caseInsensitiveMultiMap())));
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, invalidClient.getError().getErrorCode());
    }

    private static SecurityIdentity identity() {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("device-client"))
                .build();
    }

    private static RoutingContext context(SecurityIdentity identity, MultiMap parameters) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                DeviceAuthorizationRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "formAttributes" -> parameters;
                    case "absoluteURI" ->
                        "https://issuer.example/api/device?ignored=true";
                    default ->
                        throw new UnsupportedOperationException(
                                method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                DeviceAuthorizationRequestParserTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "request" -> request;
                    case "user" ->
                        identity != null ? new QuarkusHttpUser(identity) : null;
                    default ->
                        throw new UnsupportedOperationException(
                                method.toString());
                });
    }
}

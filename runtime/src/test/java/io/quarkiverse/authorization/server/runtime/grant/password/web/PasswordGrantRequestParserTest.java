package io.quarkiverse.authorization.server.runtime.grant.password.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.password.PasswordGrantRequest;
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

class PasswordGrantRequestParserTest {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("messaging-client"))
            .build();

    private final PasswordGrantRequestParser converter = new PasswordGrantRequestParser();

    @Test
    void convertsPasswordGrantRequest() {
        MultiMap parameters = validParameters()
                .add("scope", "message.read message.write")
                .add("tenant", "internal");

        PasswordGrantRequest authentication = this.converter.parse(context(parameters));

        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals("resource-owner", authentication.getUsername());
        assertEquals("resource-owner-password", authentication.getPassword());
        assertEquals(Set.of("message.read", "message.write"), authentication.getScopes());
        assertEquals(Map.of("tenant", "internal"), authentication.getAdditionalParameters());
        assertFalse(authentication.getAdditionalParameters().containsKey("username"));
        assertFalse(authentication.getAdditionalParameters().containsKey("password"));
    }

    @Test
    void returnsNullForAnotherGrantType() {
        MultiMap parameters = validParameters().set("grant_type", "authorization_code");

        assertNull(this.converter.parse(context(parameters)));
    }

    @Test
    void acceptsAnOmittedScope() {
        PasswordGrantRequest authentication = this.converter.parse(context(validParameters()));

        assertEquals(Set.of(), authentication.getScopes());
    }

    @Test
    void rejectsRepeatedGrantType() {
        assertInvalidParameter(validParameters().add("grant_type", "password"), "grant_type");
    }

    @Test
    void rejectsMissingRepeatedAndBlankUsername() {
        assertInvalidParameter(validParameters().remove("username"), "username");
        assertInvalidParameter(validParameters().add("username", "another-owner"), "username");
        assertInvalidParameter(validParameters().set("username", " "), "username");
    }

    @Test
    void rejectsMissingRepeatedAndBlankPassword() {
        assertInvalidParameter(validParameters().remove("password"), "password");
        assertInvalidParameter(validParameters().add("password", "another-password"), "password");
        assertInvalidParameter(validParameters().set("password", " "), "password");
    }

    @Test
    void rejectsRepeatedBlankAndMalformedScope() {
        assertInvalidParameter(
                validParameters().add("scope", "message.read").add("scope", "message.write"),
                "scope");
        assertInvalidParameter(validParameters().add("scope", " "), "scope");
        assertInvalidParameter(
                validParameters().add("scope", "message.read  message.write"), "scope");
    }

    @Test
    void requiresAnAuthenticatedClientPrincipal() {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(validParameters(), null)));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
    }

    private void assertInvalidParameter(MultiMap parameters, String parameterName) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(parameters)));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals(
                "OAuth 2.0 Parameter: " + parameterName, exception.getError().getDescription());
        assertEquals(ERROR_URI, exception.getError().getUri());
    }

    private static MultiMap validParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add("grant_type", "password")
                .add("username", "resource-owner")
                .add("password", "resource-owner-password");
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, new QuarkusHttpUser(CLIENT_PRINCIPAL));
    }

    private static RoutingContext context(MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                PasswordGrantRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                PasswordGrantRequestParserTest.class.getClassLoader(),
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

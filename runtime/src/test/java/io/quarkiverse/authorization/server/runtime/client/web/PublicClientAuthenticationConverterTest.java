package io.quarkiverse.authorization.server.runtime.client.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

class PublicClientAuthenticationConverterTest {

    private final PublicClientAuthenticationConverter converter = new PublicClientAuthenticationConverter();

    @Test
    void identifiesClientWithoutDependingOnGrantOrPkceParameters() {
        for (MultiMap parameters : new MultiMap[] {
                validParameters(),
                validParameters().remove("code_verifier"),
                validParameters().set("grant_type", "refresh_token"),
                validParameters().set("grant_type", "password"),
                MultiMap.caseInsensitiveMultiMap().add("client_id", "public-client"),
                validParameters().add("code_verifier", "duplicate-for-the-grant-to-reject")
        }) {
            OAuth2ClientAuthenticationToken authentication = this.converter.convert(context(parameters));
            assertEquals("public-client", authentication.getPrincipal());
            assertEquals(
                    ClientAuthenticationMethod.NONE,
                    authentication.getClientAuthenticationMethod());
            assertNull(authentication.getCredentials());
        }
    }

    @Test
    void doesNotTreatMissingClientOrUnsupportedCredentialsAsPublicAuthentication() {
        assertNull(this.converter.convert(context(validParameters().remove("client_id"))));
        for (String credential : new String[] { "client_secret", "client_assertion", "client_assertion_type" }) {
            assertNull(
                    this.converter.convert(
                            context(validParameters().add(credential, "unsupported"))));
        }
        assertNull(this.converter.convert(context(validParameters(), "Bearer token")));
    }

    @Test
    void rejectsBlankAndRepeatedClientId() {
        assertInvalidRequest(validParameters().set("client_id", " "));
        assertInvalidRequest(validParameters().add("client_id", "another-client"));
    }

    private void assertInvalidRequest(MultiMap parameters) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.convert(context(parameters)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
    }

    private static MultiMap validParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add("grant_type", "authorization_code")
                .add("client_id", "public-client")
                .add("code", "authorization-code")
                .add("code_verifier", "verifier");
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, null);
    }

    private static RoutingContext context(MultiMap parameters, String authorization) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                PublicClientAuthenticationConverterTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("getHeader".equals(method.getName()))
                        return authorization;
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                PublicClientAuthenticationConverterTest.class.getClassLoader(),
                new Class<?>[] { RoutingContext.class },
                (proxy, method, arguments) -> {
                    if ("request".equals(method.getName())) {
                        return request;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
    }
}

package io.quarkiverse.authorization.server.runtime.grant.clientcredentials.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.clientcredentials.ClientCredentialsRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;

class ClientCredentialsRequestParserTest {

    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("machine-client"))
            .build();

    private final ClientCredentialsRequestParser converter = new ClientCredentialsRequestParser();

    @Test
    void convertsClientCredentialsAndPreservesAdditionalParameterMultiplicity() {
        MultiMap parameters = validParameters()
                .add(OAuth2ParameterNames.SCOPE, "message.read message.write message.read")
                .add("custom", "value")
                .add(OAuth2ParameterNames.RESOURCE, "one")
                .add(OAuth2ParameterNames.RESOURCE, "two");

        ClientCredentialsRequest authentication = this.converter.parse(context(parameters));

        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, authentication.getGrantType());
        assertEquals(Set.of("message.read", "message.write"), authentication.getScopes());
        assertEquals("value", authentication.getAdditionalParameters().get("custom"));
        assertArrayEquals(
                new String[] { "one", "two" },
                (String[]) authentication
                        .getAdditionalParameters()
                        .get(OAuth2ParameterNames.RESOURCE));
        assertFalse(
                authentication
                        .getAdditionalParameters()
                        .containsKey(OAuth2ParameterNames.GRANT_TYPE));
        assertFalse(
                authentication.getAdditionalParameters().containsKey(OAuth2ParameterNames.SCOPE));
    }

    @Test
    void treatsMissingEmptyAndBlankScopeAsUnspecified() {
        assertEquals(Set.of(), this.converter.parse(context(validParameters())).getScopes());
        for (String scope : new String[] { "", " ", "\t" }) {
            assertEquals(
                    Set.of(),
                    this.converter
                            .parse(
                                    context(
                                            validParameters()
                                                    .add(OAuth2ParameterNames.SCOPE, scope)))
                            .getScopes());
        }
    }

    @Test
    void returnsNullForMissingBlankOrDifferentGrantBeforeResolvingClient() {
        assertNull(
                this.converter.parse(
                        context(validParameters().remove(OAuth2ParameterNames.GRANT_TYPE), null)));
        for (String grant : new String[] { "", " ", "password", "authorization_code", "refresh_token" }) {
            assertNull(
                    this.converter.parse(
                            context(
                                    validParameters().set(OAuth2ParameterNames.GRANT_TYPE, grant),
                                    null)));
        }
    }

    @Test
    void rejectsRepeatedNonBlankScope() {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(
                        context(
                                validParameters()
                                        .add(
                                                OAuth2ParameterNames.SCOPE,
                                                "message.read")
                                        .add(
                                                OAuth2ParameterNames.SCOPE,
                                                "message.write"))));

        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals("OAuth 2.0 Parameter: scope", exception.getError().getDescription());
        assertEquals(
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI, exception.getError().getUri());
    }

    @Test
    void ignoresOptionalScopeWhenFirstValueIsBlank() {
        // The optional-scope parser checks multiplicity only when the first scope has text.
        ClientCredentialsRequest authentication = this.converter.parse(
                context(
                        validParameters()
                                .add(OAuth2ParameterNames.SCOPE, "")
                                .add(OAuth2ParameterNames.SCOPE, "message.read")));

        assertEquals(Set.of(), authentication.getScopes());
    }

    @Test
    void preservesEmptyScopeTokensForValidatorInsteadOfNormalizingWhitespace() {
        for (String scope : new String[] { " message.read", "message.read ", "message.read  message.write" }) {
            Set<String> parsed = this.converter
                    .parse(
                            context(
                                    validParameters()
                                            .add(OAuth2ParameterNames.SCOPE, scope)))
                    .getScopes();
            assertEquals(
                    scope.contains("message.write")
                            ? Set.of("", "message.read", "message.write")
                            : Set.of("", "message.read"),
                    parsed);
        }
    }

    @Test
    void requiresQuarkusClientPrincipal() {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(validParameters(), null)));

        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
    }

    private static MultiMap validParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add(
                        OAuth2ParameterNames.GRANT_TYPE,
                        AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, new QuarkusHttpUser(CLIENT_PRINCIPAL));
    }

    private static RoutingContext context(MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                ClientCredentialsRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                ClientCredentialsRequestParserTest.class.getClassLoader(),
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

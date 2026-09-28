package io.quarkiverse.authorization.server.runtime.grant.tokenexchange.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.tokenexchange.TokenExchangeRequest;
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

class TokenExchangeRequestParserTest {

    private static final String ACCESS_TOKEN_TYPE = TokenExchangeRequestParser.ACCESS_TOKEN_TYPE_VALUE;
    private static final String JWT_TOKEN_TYPE = TokenExchangeRequestParser.JWT_TOKEN_TYPE_VALUE;
    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("exchange-client"))
            .build();

    private final TokenExchangeRequestParser converter = new TokenExchangeRequestParser();

    @Test
    void convertsAllParametersAndPreservesProtocolMultiplicity() {
        MultiMap parameters = validParameters()
                .add(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, JWT_TOKEN_TYPE)
                .add(OAuth2ParameterNames.ACTOR_TOKEN, "actor-token")
                .add(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE)
                .add(OAuth2ParameterNames.SCOPE, "message.read message.write message.read")
                .add(OAuth2ParameterNames.RESOURCE, "https://resource.example.com/messages")
                .add(OAuth2ParameterNames.RESOURCE, "urn:example:resource")
                .add(OAuth2ParameterNames.AUDIENCE, "messages-api")
                .add(OAuth2ParameterNames.AUDIENCE, "audit-api")
                .add("custom", "one")
                .add("custom", "two");

        TokenExchangeRequest authentication = this.converter.parse(context(parameters));

        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals(AuthorizationGrantType.TOKEN_EXCHANGE, authentication.getGrantType());
        assertEquals(
                List.of("https://resource.example.com/messages", "urn:example:resource"),
                authentication.getResources());
        assertEquals(List.of("messages-api", "audit-api"), authentication.getAudiences());
        assertEquals(Set.of("message.read", "message.write"), authentication.getScopes());
        assertEquals(JWT_TOKEN_TYPE, authentication.getRequestedTokenType());
        assertEquals("subject-token", authentication.getSubjectToken());
        assertEquals(ACCESS_TOKEN_TYPE, authentication.getSubjectTokenType());
        assertEquals("actor-token", authentication.getActorToken());
        assertEquals(ACCESS_TOKEN_TYPE, authentication.getActorTokenType());
        assertArrayEquals(
                new String[] { "one", "two" },
                (String[]) authentication.getAdditionalParameters().get("custom"));
        for (String protocolParameter : List.of(
                OAuth2ParameterNames.GRANT_TYPE,
                OAuth2ParameterNames.RESOURCE,
                OAuth2ParameterNames.AUDIENCE,
                OAuth2ParameterNames.REQUESTED_TOKEN_TYPE,
                OAuth2ParameterNames.SUBJECT_TOKEN,
                OAuth2ParameterNames.SUBJECT_TOKEN_TYPE,
                OAuth2ParameterNames.ACTOR_TOKEN,
                OAuth2ParameterNames.ACTOR_TOKEN_TYPE,
                OAuth2ParameterNames.SCOPE)) {
            assertFalse(authentication.getAdditionalParameters().containsKey(protocolParameter));
        }
    }

    @Test
    void defaultsRequestedTokenTypeAndTreatsOptionalValuesAsEmpty() {
        TokenExchangeRequest authentication = this.converter.parse(context(validParameters()));

        assertEquals(ACCESS_TOKEN_TYPE, authentication.getRequestedTokenType());
        assertTrue(authentication.getResources().isEmpty());
        assertTrue(authentication.getAudiences().isEmpty());
        assertTrue(authentication.getScopes().isEmpty());
        assertNull(authentication.getActorToken());
        assertNull(authentication.getActorTokenType());
    }

    @Test
    void returnsNullForOtherGrantBeforeResolvingClient() {
        assertNull(
                this.converter.parse(
                        context(
                                validParameters()
                                        .set(
                                                OAuth2ParameterNames.GRANT_TYPE,
                                                AuthorizationGrantType.PASSWORD.getValue()),
                                null)));
        assertNull(
                this.converter.parse(
                        context(validParameters().remove(OAuth2ParameterNames.GRANT_TYPE), null)));
    }

    @Test
    void rejectsMissingBlankOrRepeatedSubjectParameters() {
        for (String parameter : List.of(
                OAuth2ParameterNames.SUBJECT_TOKEN,
                OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)) {
            assertInvalidRequest(validParameters().remove(parameter), parameter);
            assertInvalidRequest(validParameters().set(parameter, " "), parameter);
            assertInvalidRequest(
                    validParameters()
                            .add(
                                    parameter,
                                    OAuth2ParameterNames.SUBJECT_TOKEN.equals(parameter)
                                            ? "another-token"
                                            : JWT_TOKEN_TYPE),
                    parameter);
        }
    }

    @Test
    void rejectsUnpairedOrRepeatedActorParameters() {
        assertInvalidRequest(
                validParameters().add(OAuth2ParameterNames.ACTOR_TOKEN, "actor-token"),
                OAuth2ParameterNames.ACTOR_TOKEN_TYPE);
        assertInvalidRequest(
                validParameters().add(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE),
                OAuth2ParameterNames.ACTOR_TOKEN);
        assertInvalidRequest(
                validParameters()
                        .add(OAuth2ParameterNames.ACTOR_TOKEN, "actor-token")
                        .add(OAuth2ParameterNames.ACTOR_TOKEN, "another-token")
                        .add(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE),
                OAuth2ParameterNames.ACTOR_TOKEN);
        assertInvalidRequest(
                validParameters()
                        .add(OAuth2ParameterNames.ACTOR_TOKEN, "actor-token")
                        .add(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE)
                        .add(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, JWT_TOKEN_TYPE),
                OAuth2ParameterNames.ACTOR_TOKEN_TYPE);
    }

    @Test
    void rejectsRepeatedRequestedTypeAndNonBlankScope() {
        assertInvalidRequest(
                validParameters()
                        .add(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE)
                        .add(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, JWT_TOKEN_TYPE),
                OAuth2ParameterNames.REQUESTED_TOKEN_TYPE);
        assertInvalidRequest(
                validParameters()
                        .add(OAuth2ParameterNames.SCOPE, "message.read")
                        .add(OAuth2ParameterNames.SCOPE, "message.write"),
                OAuth2ParameterNames.SCOPE);
    }

    @Test
    void ignoresOptionalScopeWhenFirstValueIsBlank() {
        TokenExchangeRequest authentication = this.converter.parse(
                context(
                        validParameters()
                                .add(OAuth2ParameterNames.SCOPE, "")
                                .add(OAuth2ParameterNames.SCOPE, "message.read")));

        assertTrue(authentication.getScopes().isEmpty());
    }

    @Test
    void rejectsUnsupportedTokenTypesForEveryTypeParameter() {
        for (String parameter : List.of(
                OAuth2ParameterNames.REQUESTED_TOKEN_TYPE,
                OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)) {
            MultiMap parameters = validParameters().set(parameter, "urn:example:unsupported");
            assertUnsupportedTokenType(parameters, parameter);
        }
        assertUnsupportedTokenType(
                validParameters()
                        .add(OAuth2ParameterNames.ACTOR_TOKEN, "actor-token")
                        .add(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, "urn:example:unsupported"),
                OAuth2ParameterNames.ACTOR_TOKEN_TYPE);
    }

    @Test
    void acceptsOnlyAbsoluteResourceUrisWithoutFragments() {
        for (String invalid : List.of(
                "",
                "relative/path",
                "https://resource.example.com/path#fragment",
                "http://[")) {
            assertInvalidRequest(
                    validParameters().add(OAuth2ParameterNames.RESOURCE, invalid),
                    OAuth2ParameterNames.RESOURCE);
        }
        assertEquals(
                List.of("https://resource.example.com/path", "urn:example:resource"),
                this.converter
                        .parse(
                                context(
                                        validParameters()
                                                .add(
                                                        OAuth2ParameterNames.RESOURCE,
                                                        "https://resource.example.com/path")
                                                .add(
                                                        OAuth2ParameterNames.RESOURCE,
                                                        "urn:example:resource")))
                        .getResources());
    }

    @Test
    void requiresQuarkusClientPrincipal() {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(validParameters(), null)));
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, exception.getError().getErrorCode());
    }

    private void assertInvalidRequest(MultiMap parameters, String parameterName) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(parameters)));
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, exception.getError().getErrorCode());
        assertEquals(
                "OAuth 2.0 Parameter: " + parameterName, exception.getError().getDescription());
        assertEquals(
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI, exception.getError().getUri());
    }

    private void assertUnsupportedTokenType(MultiMap parameters, String parameterName) {
        OAuth2AuthenticationException exception = assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.converter.parse(context(parameters)));
        assertEquals(OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE, exception.getError().getErrorCode());
        assertEquals(
                "OAuth 2.0 Token Exchange parameter: " + parameterName,
                exception.getError().getDescription());
        assertEquals(
                "https://datatracker.ietf.org/doc/html/rfc8693#section-3",
                exception.getError().getUri());
    }

    private static MultiMap validParameters() {
        return MultiMap.caseInsensitiveMultiMap()
                .add(
                        OAuth2ParameterNames.GRANT_TYPE,
                        AuthorizationGrantType.TOKEN_EXCHANGE.getValue())
                .add(OAuth2ParameterNames.SUBJECT_TOKEN, "subject-token")
                .add(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
    }

    private static RoutingContext context(MultiMap parameters) {
        return context(parameters, new QuarkusHttpUser(CLIENT_PRINCIPAL));
    }

    private static RoutingContext context(MultiMap parameters, User user) {
        HttpServerRequest request = (HttpServerRequest) Proxy.newProxyInstance(
                TokenExchangeRequestParserTest.class.getClassLoader(),
                new Class<?>[] { HttpServerRequest.class },
                (proxy, method, arguments) -> {
                    if ("formAttributes".equals(method.getName())) {
                        return parameters;
                    }
                    throw new UnsupportedOperationException(method.toString());
                });
        return (RoutingContext) Proxy.newProxyInstance(
                TokenExchangeRequestParserTest.class.getClassLoader(),
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

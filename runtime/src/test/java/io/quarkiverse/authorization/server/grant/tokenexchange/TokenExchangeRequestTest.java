package io.quarkiverse.authorization.server.grant.tokenexchange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class TokenExchangeRequestTest {

    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";
    private static final SecurityIdentity CLIENT_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("exchange-client"))
            .build();

    @Test
    void retainsClientAndDefensivelyCopiesRequestValues() {
        List<String> resources = new ArrayList<>(List.of("https://resource.example.com"));
        List<String> audiences = new ArrayList<>(List.of("messages"));
        Set<String> scopes = new HashSet<>(Set.of("message.read"));
        Map<String, Object> additionalParameters = new HashMap<>(Map.of("custom", "value"));

        TokenExchangeRequest authentication = new TokenExchangeRequest(
                resources,
                audiences,
                scopes,
                JWT_TOKEN_TYPE,
                "subject-token",
                ACCESS_TOKEN_TYPE,
                "actor-token",
                JWT_TOKEN_TYPE,
                CLIENT_PRINCIPAL,
                additionalParameters);
        resources.clear();
        audiences.clear();
        scopes.clear();
        additionalParameters.clear();

        assertSame(CLIENT_PRINCIPAL, authentication.getClientPrincipal());
        assertEquals(AuthorizationGrantType.TOKEN_EXCHANGE, authentication.getGrantType());
        assertEquals(List.of("https://resource.example.com"), authentication.getResources());
        assertEquals(List.of("messages"), authentication.getAudiences());
        assertEquals(Set.of("message.read"), authentication.getScopes());
        assertEquals(JWT_TOKEN_TYPE, authentication.getRequestedTokenType());
        assertEquals("subject-token", authentication.getSubjectToken());
        assertEquals(ACCESS_TOKEN_TYPE, authentication.getSubjectTokenType());
        assertEquals("actor-token", authentication.getActorToken());
        assertEquals(JWT_TOKEN_TYPE, authentication.getActorTokenType());
        assertEquals(Map.of("custom", "value"), authentication.getAdditionalParameters());
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getResources().add("another"));
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getAudiences().add("another"));
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.getScopes().add("message.write"));
    }

    @Test
    void treatsNullableOptionalValuesAsEmptyOrNull() {
        TokenExchangeRequest authentication = new TokenExchangeRequest(
                List.of(),
                List.of(),
                null,
                ACCESS_TOKEN_TYPE,
                "subject-token",
                ACCESS_TOKEN_TYPE,
                null,
                null,
                CLIENT_PRINCIPAL,
                null);

        assertTrue(authentication.getResources().isEmpty());
        assertTrue(authentication.getAudiences().isEmpty());
        assertTrue(authentication.getScopes().isEmpty());
        assertNull(authentication.getActorToken());
        assertNull(authentication.getActorTokenType());
        assertTrue(authentication.getAdditionalParameters().isEmpty());
    }

    @Test
    void rejectsMissingRequiredValues() {
        assertThrows(
                IllegalArgumentException.class,
                () -> token(
                        null,
                        List.of(),
                        ACCESS_TOKEN_TYPE,
                        "subject-token",
                        ACCESS_TOKEN_TYPE));
        assertThrows(
                IllegalArgumentException.class,
                () -> token(
                        List.of(),
                        null,
                        ACCESS_TOKEN_TYPE,
                        "subject-token",
                        ACCESS_TOKEN_TYPE));
        for (String value : new String[] { null, "", " " }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> token(List.of(), List.of(), value, "subject-token", ACCESS_TOKEN_TYPE));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> token(List.of(), List.of(), ACCESS_TOKEN_TYPE, value, ACCESS_TOKEN_TYPE));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> token(List.of(), List.of(), ACCESS_TOKEN_TYPE, "subject-token", value));
        }
        assertThrows(
                NullPointerException.class,
                () -> new TokenExchangeRequest(
                        List.of(),
                        List.of(),
                        Set.of(),
                        ACCESS_TOKEN_TYPE,
                        "subject-token",
                        ACCESS_TOKEN_TYPE,
                        null,
                        null,
                        null,
                        Map.of()));
    }

    private static TokenExchangeRequest token(
            List<String> resources,
            List<String> audiences,
            String requestedTokenType,
            String subjectToken,
            String subjectTokenType) {
        return new TokenExchangeRequest(
                resources,
                audiences,
                Set.of(),
                requestedTokenType,
                subjectToken,
                subjectTokenType,
                null,
                null,
                CLIENT_PRINCIPAL,
                Map.of());
    }
}

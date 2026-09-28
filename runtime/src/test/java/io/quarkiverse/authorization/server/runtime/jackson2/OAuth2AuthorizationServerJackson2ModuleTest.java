package io.quarkiverse.authorization.server.runtime.jackson2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

class OAuth2AuthorizationServerJackson2ModuleTest {

    @Test
    void roundTripsAuthorizationRequest() throws Exception {
        ObjectMapper jdbcMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .registerModule(new OAuth2AuthorizationServerJackson2Module());
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com/oauth2/authorize")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .scope("message.read")
                .state("request-state")
                .additionalParameters(parameters -> parameters.put("code_challenge", "challenge"))
                .attributes(attributes -> attributes.put("request-id", "request-1"))
                .build();

        String json = jdbcMapper.writeValueAsString(authorizationRequest);
        OAuth2AuthorizationRequest restored = jdbcMapper.readValue(json, OAuth2AuthorizationRequest.class);

        assertEquals(authorizationRequest.getAuthorizationUri(), restored.getAuthorizationUri());
        assertEquals(authorizationRequest.getGrantType(), restored.getGrantType());
        assertEquals(authorizationRequest.getResponseType(), restored.getResponseType());
        assertEquals(authorizationRequest.getClientId(), restored.getClientId());
        assertEquals(authorizationRequest.getRedirectUri(), restored.getRedirectUri());
        assertEquals(authorizationRequest.getScopes(), restored.getScopes());
        assertEquals(authorizationRequest.getState(), restored.getState());
        assertEquals(authorizationRequest.getAdditionalParameters(), restored.getAdditionalParameters());
        assertEquals(authorizationRequest.getAuthorizationRequestUri(), restored.getAuthorizationRequestUri());
        assertEquals(authorizationRequest.getAttributes(), restored.getAttributes());
    }

    @Test
    void roundTripsSupportedJdbcValuesWithoutChangingSourceMapper() throws Exception {
        ObjectMapper source = new ObjectMapper().registerModule(new JavaTimeModule());
        ObjectMapper jdbcMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .registerModule(new OAuth2AuthorizationServerJackson2Module());
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("duration", Duration.ofMinutes(5));
        values.put("instant", Instant.parse("2026-08-31T01:00:00Z"));
        values.put("grant_type", AuthorizationGrantType.PASSWORD);
        values.put("client_authentication_method", ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        values.put("signature_algorithm", SignatureAlgorithm.PS256);
        values.put("token_format", OAuth2TokenFormat.REFERENCE);
        values.put("token_type", OAuth2TokenType.ACCESS_TOKEN);
        values.put("scopes", new LinkedHashSet<>(List.of("message.read", "message.write")));
        values.put(
                "unmodifiable_scopes",
                Collections.unmodifiableSet(
                        new HashSet<>(List.of("message.read", "message.write"))));
        values.put("unmodifiable_audiences",
                Collections.unmodifiableList(List.of("messages-api", "audit-api")));

        Map<String, Object> unmodifiableValues = Collections.unmodifiableMap(values);
        String json = jdbcMapper.writeValueAsString(unmodifiableValues);
        Map<String, Object> restored = jdbcMapper.readValue(json, new TypeReference<>() {
        });

        assertEquals(unmodifiableValues, restored);
        assertTrue(json.contains("@class"));
        assertFalse(source.writeValueAsString(values).contains("@class"));
    }

    @Test
    void rejectsMaliciousPolymorphicTypes() {
        ObjectMapper jdbcMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .registerModule(new OAuth2AuthorizationServerJackson2Module());

        assertThrows(
                InvalidTypeIdException.class,
                () -> jdbcMapper.readValue(
                        "{\"@class\":\"java.lang.Runtime\"}",
                        new TypeReference<Map<String, Object>>() {
                        }));
        assertThrows(
                InvalidTypeIdException.class,
                () -> jdbcMapper.readValue(
                        "{\"@class\":\"io.quarkiverse.authorization.server.runtime.jackson2.SecurityIdentityJacksonBuilder\"}",
                        Object.class));
    }
}

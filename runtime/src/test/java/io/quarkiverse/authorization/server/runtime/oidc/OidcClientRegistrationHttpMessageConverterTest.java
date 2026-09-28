package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import io.vertx.core.http.HttpServerResponse;

class OidcClientRegistrationHttpMessageConverterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final OidcClientRegistrationHttpMessageConverter converter = new OidcClientRegistrationHttpMessageConverter(
            this.objectMapper);

    @Test
    void readsProtocolTypesWithoutMutatingSharedMapper() {
        var registration = this.converter.read("""
                {"redirect_uris":["https://rp.example/callback"], "client_id":"client", "client_secret":"secret",
                 "client_id_issued_at":100, "client_secret_expires_at":200, "scope":"openid profile",
                 "jwks_uri":"https://rp.example/jwks", "registration_client_uri":"https://issuer.example/register"}
                """);
        assertEquals(List.of("openid", "profile"), registration.getScopes());
        assertEquals(Instant.ofEpochSecond(100), registration.getClientIdIssuedAt());
        assertEquals(Instant.ofEpochSecond(200), registration.getClientSecretExpiresAt());
        assertEquals("https://rp.example/jwks", registration.getJwkSetUrl().toString());
        assertFalse(this.objectMapper.isEnabled(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION));
    }

    @Test
    void writesEpochSecondsSpaceDelimitedScopeAndNeverExpiringSecret() throws Exception {
        var registration = OidcClientRegistration.builder().redirectUri("https://rp.example/callback")
                .clientId("client").clientIdIssuedAt(Instant.ofEpochSecond(100)).clientSecret("secret")
                .scope("openid").scope("profile").build();
        Map<String, Object> wire = write(registration);
        assertEquals(100, wire.get("client_id_issued_at"));
        assertEquals(0, wire.get("client_secret_expires_at"));
        assertEquals("openid profile", wire.get("scope"));
        var roundTrip = this.converter.read(this.objectMapper.writeValueAsString(wire));
        assertNull(roundTrip.getClientSecretExpiresAt());
        assertEquals(registration.getClaims(), roundTrip.getClaims());
        assertEquals(200, write(OidcClientRegistration.withClaims(registration.getClaims())
                .clientSecretExpiresAt(Instant.ofEpochSecond(200)).build()).get("client_secret_expires_at"));
    }

    @Test
    void doesNotInventSecretOrExpiryForPublicClient() throws Exception {
        Map<String, Object> wire = write(OidcClientRegistration.builder().redirectUri("https://rp.example/callback")
                .clientId("public").tokenEndpointAuthenticationMethod("none").build());
        assertFalse(wire.containsKey("client_secret"));
        assertFalse(wire.containsKey("client_secret_expires_at"));
        assertFalse(wire.containsKey("registration_client_uri"));
    }

    @Test
    void rejectsDuplicateTrailingMalformedAndWronglyTypedJson() {
        for (String json : List.of("null", "[]", "{}", "{broken", "{} {}",
                "{\"redirect_uris\":[\"https://rp.example\"],\"scope\":\"openid\",\"scope\":\"profile\"}",
                "{\"redirect_uris\":[123]}", "{\"redirect_uris\":[\"https://rp.example\"],\"scope\":[\"openid\"]}",
                "{\"redirect_uris\":[\"https://rp.example\"],\"client_secret_expires_at\":0}",
                "{\"redirect_uris\":[\"https://rp.example\"],\"client_id\":\"id\",\"client_id_issued_at\":1.5}",
                "{\"redirect_uris\":[\"https://rp.example\"],\"client_id\":\"id\",\"client_id_issued_at\":-1}",
                "{\"redirect_uris\":[\"https://rp.example\"],\"client_id\":\"id\",\"client_id_issued_at\":999999999999999999999}",
                "{\"redirect_uris\":[\"https://rp.example\"],\"scope\":\"openid  profile\"}")) {
            assertThrows(IllegalArgumentException.class, () -> this.converter.read(json), json);
        }
    }

    @Test
    void retainsCustomClaimsForExplicitConvertersButDoesNotTreatThemAsSettings() throws Exception {
        var registration = this.converter.read("{\"redirect_uris\":[\"https://rp.example\"],\"custom\":{\"value\":true}}");
        assertEquals(Map.of("value", true), registration.getClaim("custom"));
        assertEquals(Map.of("value", true), write(registration).get("custom"));
        this.converter.setClientRegistrationConverter(
                claims -> OidcClientRegistration.withClaims(claims).clientName("customized").build());
        assertEquals("customized", this.converter.read("{\"redirect_uris\":[\"https://rp.example\"]}").getClientName());
        this.converter.setClientRegistrationParametersConverter(value -> Map.of("custom", value.getClientName()));
        assertEquals(Map.of("custom", "customized"), write(OidcClientRegistration.builder()
                .redirectUri("https://rp.example").clientName("customized").build()));
        assertThrows(NullPointerException.class, () -> this.converter.setClientRegistrationConverter(null));
        assertThrows(NullPointerException.class, () -> this.converter.setClientRegistrationParametersConverter(null));
    }

    private Map<String, Object> write(OidcClientRegistration registration) throws Exception {
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> contentType = new AtomicReference<>();
        HttpServerResponse response = (HttpServerResponse) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[] { HttpServerResponse.class }, (proxy, method, args) -> {
                    if (method.getName().equals("putHeader")) {
                        contentType.set(args[1].toString());
                        return proxy;
                    }
                    if (method.getName().equals("end")) {
                        body.set((String) args[0]);
                        return null;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        this.converter.write(registration, response);
        assertTrue(contentType.get().startsWith("application/json"));
        return this.objectMapper.readValue(body.get(), new TypeReference<>() {
        });
    }
}

package io.quarkiverse.authorization.server.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class OidcClientRegistrationTest {

    @Test
    void exposesClientMetadataAndRegistrationClaims() throws Exception {
        Instant issued = Instant.ofEpochSecond(100);
        OidcClientRegistration registration = OidcClientRegistration.builder().clientId("client")
                .clientIdIssuedAt(issued).clientSecret("secret").clientSecretExpiresAt(issued.plusSeconds(60))
                .clientName("Client").redirectUri("https://client.example/callback")
                .postLogoutRedirectUri("https://client.example/bye").tokenEndpointAuthenticationMethod("private_key_jwt")
                .tokenEndpointAuthenticationSigningAlgorithm("PS256").grantType("authorization_code")
                .responseType("code").scope("openid").jwkSetUrl("https://client.example/jwks")
                .idTokenSignedResponseAlgorithm("ES256").registrationAccessToken("registration-token")
                .registrationClientUrl("https://issuer.example/connect/register?client_id=client").build();
        assertEquals("client", registration.getClientId());
        assertEquals(issued, registration.getClientIdIssuedAt());
        assertEquals("secret", registration.getClientSecret());
        assertEquals(issued.plusSeconds(60), registration.getClientSecretExpiresAt());
        assertEquals("Client", registration.getClientName());
        assertEquals(List.of("https://client.example/callback"), registration.getRedirectUris());
        assertEquals(List.of("https://client.example/bye"), registration.getPostLogoutRedirectUris());
        assertEquals("private_key_jwt", registration.getTokenEndpointAuthenticationMethod());
        assertEquals("PS256", registration.getTokenEndpointAuthenticationSigningAlgorithm());
        assertEquals(List.of("authorization_code"), registration.getGrantTypes());
        assertEquals(List.of("code"), registration.getResponseTypes());
        assertEquals(List.of("openid"), registration.getScopes());
        assertEquals(new URI("https://client.example/jwks").toURL(), registration.getJwkSetUrl());
        assertEquals("ES256", registration.getIdTokenSignedResponseAlgorithm());
        assertEquals("registration-token", registration.getRegistrationAccessToken());
        assertEquals("https://issuer.example/connect/register?client_id=client",
                registration.getRegistrationClientUrl().toString());
    }

    @Test
    void requestNeedsRedirectsButNotServerIssuedFields() {
        OidcClientRegistration request = request().build();
        assertNull(request.getClientId());
        assertNull(request.getClientSecret());
        assertNull(request.getRegistrationClientUrl());
        assertThrows(IllegalArgumentException.class, () -> OidcClientRegistration.builder().build());
        assertThrows(IllegalArgumentException.class, () -> request().clientSecret("secret").build());
        assertThrows(IllegalArgumentException.class, () -> request().clientIdIssuedAt(Instant.now()).build());
        assertThrows(IllegalArgumentException.class, () -> request().clientSecretExpiresAt(Instant.now()).build());
    }

    @Test
    void validatesKnownClaimTypesAndUrlsWithoutLimitingProtocolCapabilities() {
        for (Map<String, Object> invalid : List.of(Map.<String, Object> of("redirect_uris", List.of(1)),
                Map.<String, Object> of("grant_types", "authorization_code"),
                Map.<String, Object> of("response_types", List.of()),
                Map.<String, Object> of("client_name", 123), Map.<String, Object> of("scope", List.of(" ")),
                Map.<String, Object> of("jwks_uri", "relative/url"),
                Map.<String, Object> of("registration_client_uri", "invalid"),
                Map.<String, Object> of("client_id", "client", "client_id_issued_at", 123))) {
            assertThrows(IllegalArgumentException.class, () -> request().claims(claims -> claims.putAll(invalid)).build());
        }
        // The model can describe future/remote capabilities; only the local request validator restricts them.
        assertNotNull(request().grantType("client_credentials").tokenEndpointAuthenticationMethod("private_key_jwt")
                .claim("custom", Map.of("value", true)).build());
    }

    @Test
    void supportsImmutableClaimsCopyAndListConsumers() {
        var builder = request().grantTypes(values -> values.add("authorization_code"))
                .responseTypes(values -> values.add("code")).scopes(values -> values.add("openid"))
                .postLogoutRedirectUris(values -> values.add("https://client.example/bye"));
        var original = builder.build();
        builder.scope("profile");
        var copy = OidcClientRegistration.withClaims(original.getClaims()).scope("email")
                .redirectUris(values -> values.add("https://client.example/other")).build();
        assertEquals(List.of("openid"), original.getScopes());
        assertEquals(List.of("openid", "email"), copy.getScopes());
        assertThrows(UnsupportedOperationException.class, () -> original.getClaims().clear());
        assertThrows(UnsupportedOperationException.class, () -> original.getRedirectUris().clear());
    }

    @Test
    void nullExpirationRepresentsNonExpiringSecret() {
        var response = request().clientId("client").clientSecret("secret")
                .clientSecretExpiresAt(Instant.now()).clientSecretExpiresAt(null).build();
        assertNull(response.getClientSecretExpiresAt());
        assertFalse(response.hasClaim(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT));
    }

    @Test
    void roundTripsClientRegistration() throws Exception {
        var original = request().clientId("client").scope("openid").build();
        var bytes = new ByteArrayOutputStream();
        try (var output = new ObjectOutputStream(bytes)) {
            output.writeObject(original);
        }
        try (var input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            assertEquals(original.getClaims(), ((OidcClientRegistration) input.readObject()).getClaims());
        }
    }

    private static OidcClientRegistration.Builder request() {
        return OidcClientRegistration.builder().redirectUri("https://client.example/callback");
    }
}

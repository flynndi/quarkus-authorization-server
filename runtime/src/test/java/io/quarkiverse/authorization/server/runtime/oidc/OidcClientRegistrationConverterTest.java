package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.OidcClientMetadataClaimNames;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.runtime.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import io.quarkiverse.authorization.server.runtime.oidc.converter.RegisteredClientOidcClientRegistrationConverter;

class OidcClientRegistrationConverterTest {

    private final OidcClientRegistrationRegisteredClientConverter toClient = new OidcClientRegistrationRegisteredClientConverter(
            List.of(SignatureAlgorithm.RS256, SignatureAlgorithm.ES256),
            settings -> {
            },
            settings -> {
            });
    private final RegisteredClientOidcClientRegistrationConverter toRegistration = new RegisteredClientOidcClientRegistrationConverter();

    @Test
    void appliesRegistrationDefaultsAndGeneratesIndependentIdentifiersAndSecrets() {
        var first = this.toClient.convert(request().build());
        var second = this.toClient.convert(request().build());
        assertNotEquals(first.getId(), second.getId());
        assertNotEquals(first.getClientId(), second.getClientId());
        assertNotEquals(first.getClientSecret(), second.getClientSecret());
        assertEquals(32, Base64.getUrlDecoder().decode(first.getClientId()).length);
        assertEquals(48, Base64.getUrlDecoder().decode(first.getClientSecret()).length);
        assertNotNull(first.getClientIdIssuedAt());
        assertNull(first.getClientSecretExpiresAt());
        assertEquals(
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                first.getClientAuthenticationMethods());
        assertEquals(
                Set.of(AuthorizationGrantType.AUTHORIZATION_CODE),
                first.getAuthorizationGrantTypes());
        assertTrue(first.getClientSettings().isRequireProofKey());
        assertTrue(first.getClientSettings().isRequireAuthorizationConsent());
        assertEquals(
                SignatureAlgorithm.RS256, first.getTokenSettings().getIdTokenSignatureAlgorithm());
        assertNull(this.toRegistration.map(first).getRegistrationClientUrl());
    }

    @Test
    void publicClientStaysPublicAndPreservesMetadata() {
        var client = this.toClient.convert(
                request()
                        .clientName("Public RP")
                        .tokenEndpointAuthenticationMethod("none")
                        .grantType("authorization_code")
                        .grantType("refresh_token")
                        .responseType("code")
                        .scope("openid")
                        .scope("profile")
                        .postLogoutRedirectUri("https://rp.example/bye")
                        .idTokenSignedResponseAlgorithm("ES256")
                        .build());
        assertEquals(
                Set.of(ClientAuthenticationMethod.NONE), client.getClientAuthenticationMethods());
        assertNull(client.getClientSecret());
        var registration = this.toRegistration.map(client);
        assertEquals("none", registration.getTokenEndpointAuthenticationMethod());
        assertNull(registration.getClientSecret());
        assertEquals("Public RP", registration.getClientName());
        assertEquals(List.of("authorization_code", "refresh_token"), registration.getGrantTypes());
        assertEquals(List.of("code"), registration.getResponseTypes());
        assertEquals(List.of("openid", "profile"), registration.getScopes());
        assertEquals(List.of("https://rp.example/bye"), registration.getPostLogoutRedirectUris());
        assertEquals("ES256", registration.getIdTokenSignedResponseAlgorithm());
        assertFalse(registration.hasClaim(OidcClientMetadataClaimNames.REGISTRATION_ACCESS_TOKEN));
    }

    @ParameterizedTest
    @ValueSource(strings = { "client_secret_basic", "client_secret_post" })
    void preservesExplicitSecretAuthenticationMethodAndGeneratesSecret(String method) {
        var client = this.toClient.convert(
                OidcClientRegistrationConverterTest.request().tokenEndpointAuthenticationMethod(method).build());
        assertEquals(Set.of(new ClientAuthenticationMethod(method)), client.getClientAuthenticationMethods());
        assertNotNull(client.getClientSecret());
        assertEquals(method, this.toRegistration.map(client).getTokenEndpointAuthenticationMethod());
    }

    @Test
    void defaultsMissingResponseTypeToCode() {
        var client = this.toClient.convert(
                request().grantType("password").grantType("refresh_token").build());
        assertEquals(
                Set.of(
                        AuthorizationGrantType.PASSWORD,
                        AuthorizationGrantType.REFRESH_TOKEN,
                        AuthorizationGrantType.AUTHORIZATION_CODE),
                client.getAuthorizationGrantTypes());
    }

    @Test
    void clientCredentialsRegistrationRetainsOidcResponseTypeAndRedirectRequirements() {
        var client = this.toClient.convert(
                request().grantType("client_credentials").scope("message.read").build());
        assertEquals(
                Set.of(
                        AuthorizationGrantType.CLIENT_CREDENTIALS,
                        AuthorizationGrantType.AUTHORIZATION_CODE),
                client.getAuthorizationGrantTypes());
        assertEquals(Set.of("https://rp.example/callback"), client.getRedirectUris());
        var response = this.toRegistration.map(client);
        assertEquals(
                Set.of("client_credentials", "authorization_code"),
                Set.copyOf(response.getGrantTypes()));
        assertEquals(List.of("code"), response.getResponseTypes());

        assertThrows(
                IllegalArgumentException.class,
                () -> OidcClientRegistration.builder().grantType("client_credentials").build());
        assertThrows(
                IllegalArgumentException.class,
                () -> request().grantType("client_credentials").responseTypes(List::clear).build());
    }

    @Test
    void deviceRegistrationPreservesGrantAndPublicAuthenticationMethod() {
        var client = this.toClient.convert(
                request()
                        .tokenEndpointAuthenticationMethod("none")
                        .grantType(AuthorizationGrantType.DEVICE_CODE.getValue())
                        .scope("message.read")
                        .build());

        assertEquals(
                Set.of(
                        AuthorizationGrantType.DEVICE_CODE,
                        AuthorizationGrantType.AUTHORIZATION_CODE),
                client.getAuthorizationGrantTypes());
        assertEquals(
                Set.of(ClientAuthenticationMethod.NONE), client.getClientAuthenticationMethods());
        var response = this.toRegistration.map(client);
        assertEquals(
                Set.of(
                        AuthorizationGrantType.DEVICE_CODE.getValue(),
                        AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
                Set.copyOf(response.getGrantTypes()));
        assertEquals("none", response.getTokenEndpointAuthenticationMethod());
    }

    @Test
    void responsePreservesFiniteSecretExpiryAndAllowsMissingIssueTime() {
        Instant expiry = Instant.now().plusSeconds(3600);
        var client = RegisteredClient.from(this.toClient.convert(request().build()))
                .clientIdIssuedAt(null)
                .clientSecretExpiresAt(expiry)
                .build();
        var registration = this.toRegistration.map(client);
        assertNull(registration.getClientIdIssuedAt());
        assertEquals(expiry, registration.getClientSecretExpiresAt());
        assertEquals(client.getClientSecret(), registration.getClientSecret());
    }

    @Test
    void converterCannotBypassUnsupportedMetadataOrUnavailableSigningKeys() {
        assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.toClient.convert(
                        request()
                                .tokenEndpointAuthenticationMethod("private_key_jwt")
                                .build()));
        assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.toClient.convert(
                        request().idTokenSignedResponseAlgorithm("PS256").build()));
        assertThrows(
                OAuth2AuthenticationException.class,
                () -> new OidcClientRegistrationRegisteredClientConverter(
                        List.of(SignatureAlgorithm.ES256),
                        settings -> {
                        },
                        settings -> {
                        })
                        .convert(request().build()));
        assertThrows(
                OAuth2AuthenticationException.class,
                () -> this.toClient.convert(
                        request()
                                .clientId("chosen-by-request")
                                .clientSecret("injected")
                                .build()));
    }

    private static OidcClientRegistration.Builder request() {
        return OidcClientRegistration.builder().redirectUri("https://rp.example/callback");
    }
}

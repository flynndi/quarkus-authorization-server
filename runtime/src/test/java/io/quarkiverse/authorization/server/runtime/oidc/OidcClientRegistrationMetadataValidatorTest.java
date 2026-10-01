package io.quarkiverse.authorization.server.runtime.oidc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientRegistrationMetadataValidator;

class OidcClientRegistrationMetadataValidatorTest {

    private final OidcClientRegistrationMetadataValidator validator = new OidcClientRegistrationMetadataValidator(
            List.of(SignatureAlgorithm.RS256));

    @Test
    void acceptsCurrentConfidentialAndPublicCapabilities() {
        assertDoesNotThrow(() -> this.validator.validateSupportedMetadata(request().build()));
        assertDoesNotThrow(() -> this.validator.validateSupportedMetadata(
                OidcClientRegistrationMetadataValidatorTest.request().tokenEndpointAuthenticationMethod("client_secret_post")
                        .grantType("client_credentials").scope("message.read").build()));
        assertDoesNotThrow(() -> this.validator.validateSupportedMetadata(request().tokenEndpointAuthenticationMethod("none")
                .grantType("authorization_code").responseType("code").scope("openid").scope("message.read").build()));
        assertDoesNotThrow(() -> this.validator
                .validateSupportedMetadata(request().tokenEndpointAuthenticationMethod("client_secret_basic")
                        .grantType("password").grantType("refresh_token").idTokenSignedResponseAlgorithm("RS256").build()));
        assertDoesNotThrow(() -> this.validator
                .validateSupportedMetadata(request().tokenEndpointAuthenticationMethod("client_secret_basic")
                        .grantType("client_credentials").scope("message.read").build()));
        assertDoesNotThrow(() -> this.validator.validateSupportedMetadata(request().tokenEndpointAuthenticationMethod("none")
                .grantType("urn:ietf:params:oauth:grant-type:device_code").scope("message.read").build()));
        assertDoesNotThrow(() -> this.validator
                .validateSupportedMetadata(request().tokenEndpointAuthenticationMethod("client_secret_basic")
                        .grantType("urn:ietf:params:oauth:grant-type:token-exchange").scope("message.read").build()));
    }

    @Test
    void rejectsUnsupportedGrantsResponsesAndAuthenticationMethods() {
        for (String grant : List.of("custom", "urn:example:unsupported-grant")) {
            assertError("invalid_client_metadata", "grant_types", request().grantType(grant).build());
        }
        for (String response : List.of("token", "id_token", "code id_token")) {
            assertError("invalid_client_metadata", "response_types", request().responseType(response).build());
        }
        for (String method : List.of("unknown")) {
            assertError("invalid_client_metadata", "token_endpoint_auth_method",
                    request().tokenEndpointAuthenticationMethod(method).build());
        }
        assertError("invalid_client_metadata", "grant_types", request().tokenEndpointAuthenticationMethod("none")
                .grantType("password").build());
    }

    @Test
    void rejectsServerOwnedAndUnimplementedMetadataInsteadOfDroppingIt() {
        for (Map<String, Object> claims : List.of(Map.<String, Object> of("client_id", "injected"),
                Map.<String, Object> of("client_id", "injected", "client_secret", "chosen-secret"),
                Map.<String, Object> of("client_id", "injected", "client_id_issued_at", Instant.now()),
                Map.<String, Object> of("registration_access_token", "chosen-token"),
                Map.<String, Object> of("registration_client_uri", "https://evil.example/register"),
                Map.<String, Object> of("jwks_uri", "https://rp.example/jwks"),
                Map.<String, Object> of("token_endpoint_auth_signing_alg", "RS256"),
                Map.<String, Object> of("id_token_encrypted_response_alg", "RSA-OAEP"),
                Map.<String, Object> of("require_proof_key", false), Map.<String, Object> of("custom", true))) {
            var error = assertThrows(OAuth2AuthenticationException.class,
                    () -> this.validator.validateSupportedMetadata(request().claims(values -> values.putAll(claims)).build()));
            assertEquals("invalid_client_metadata", error.getError().getErrorCode());
        }
    }

    @Test
    void rejectsJwtRegistrationWithMissingKeysOrIncompatibleAlgorithms() {
        assertError("invalid_client_metadata", "jwks_uri", OidcClientRegistrationMetadataValidatorTest.request()
                .tokenEndpointAuthenticationMethod("private_key_jwt").build());
        assertError("invalid_client_metadata", "token_endpoint_auth_signing_alg",
                OidcClientRegistrationMetadataValidatorTest.request()
                        .tokenEndpointAuthenticationMethod("private_key_jwt").jwkSetUrl("https://rp.example/jwks")
                        .tokenEndpointAuthenticationSigningAlgorithm("HS256").build());
        assertError("invalid_client_metadata", "token_endpoint_auth_signing_alg",
                OidcClientRegistrationMetadataValidatorTest.request()
                        .tokenEndpointAuthenticationMethod("client_secret_jwt")
                        .tokenEndpointAuthenticationSigningAlgorithm("RS256").build());
        for (String url : List.of("http://127.0.0.1/jwks", "http://rp.example/jwks", "file:/tmp/keys.json",
                "https://user:password@rp.example/jwks",
                "https://rp.example/jwks#fragment")) {
            assertError("invalid_client_metadata", "jwks_uri", OidcClientRegistrationMetadataValidatorTest.request()
                    .tokenEndpointAuthenticationMethod("private_key_jwt").jwkSetUrl(url).build());
        }
    }

    @Test
    void certificateRegistrationRequiresCompatibleSubjectOrJwksMetadata() {
        for (Object dn : List.of("", " ", "not a DN", 42, List.of("CN=client"))) {
            assertError("invalid_client_metadata", "tls_client_auth_subject_dn",
                    OidcClientRegistrationMetadataValidatorTest.request()
                            .tokenEndpointAuthenticationMethod("tls_client_auth").claim("tls_client_auth_subject_dn", dn)
                            .build());
        }
        assertError("invalid_client_metadata", "tls_client_auth_subject_dn",
                OidcClientRegistrationMetadataValidatorTest.request()
                        .tokenEndpointAuthenticationMethod("tls_client_auth").build());
        assertError("invalid_client_metadata", "jwks_uri", OidcClientRegistrationMetadataValidatorTest.request()
                .tokenEndpointAuthenticationMethod("self_signed_tls_client_auth").build());
        assertError("invalid_client_metadata", "tls_client_auth_subject_dn",
                OidcClientRegistrationMetadataValidatorTest.request()
                        .tokenEndpointAuthenticationMethod("self_signed_tls_client_auth").jwkSetUrl("https://rp.example/jwks")
                        .tlsClientAuthSubjectDn("CN=client").build());
        assertError("invalid_client_metadata", "token_endpoint_auth_signing_alg",
                OidcClientRegistrationMetadataValidatorTest.request()
                        .tokenEndpointAuthenticationMethod("self_signed_tls_client_auth").jwkSetUrl("https://rp.example/jwks")
                        .tokenEndpointAuthenticationSigningAlgorithm("RS256").build());
        for (String claim : List.of("tls_client_auth_san_dns", "tls_client_certificate_bound_access_tokens", "jwks")) {
            assertError("invalid_client_metadata", claim, OidcClientRegistrationMetadataValidatorTest.request()
                    .claim(claim, "unsupported").build());
        }
    }

    @Test
    void rejectsInvalidAndRegistrationControlScopes() {
        for (String scope : List.of("bad scope", "bad\"scope", "bad\\scope", "中文", "client.create", "client.read")) {
            assertError("invalid_client_metadata", "scope", request().scope(scope).build());
        }
    }

    @Test
    void doesNotAdvertiseAnAlgorithmJustBecauseItsEnumExists() {
        for (String algorithm : List.of("none", "HS256", "ES256", "PS256", "unknown")) {
            assertError("invalid_client_metadata", "id_token_signed_response_alg",
                    request().idTokenSignedResponseAlgorithm(algorithm).build());
        }
    }

    private void assertError(String code, String field, OidcClientRegistration registration) {
        var error = assertThrows(OAuth2AuthenticationException.class,
                () -> this.validator.validateSupportedMetadata(registration)).getError();
        assertEquals(code, error.getErrorCode());
        assertEquals("Invalid Client Registration: " + field, error.getDescription());
    }

    private static OidcClientRegistration.Builder request() {
        return OidcClientRegistration.builder().redirectUri("https://rp.example/callback");
    }
}

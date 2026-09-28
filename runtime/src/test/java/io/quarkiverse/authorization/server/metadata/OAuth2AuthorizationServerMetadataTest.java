package io.quarkiverse.authorization.server.metadata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class OAuth2AuthorizationServerMetadataTest {

    @Test
    void buildsMetadataAndExposesTypedClaims() {
        OAuth2AuthorizationServerMetadata metadata = OAuth2AuthorizationServerMetadata.builder()
                .issuer("https://issuer.example.com")
                .authorizationEndpoint("https://issuer.example.com/oauth2/authorize")
                .tokenEndpoint("https://issuer.example.com/oauth2/token")
                .tokenEndpointAuthenticationMethod("client_secret_basic")
                .jwkSetUrl("https://issuer.example.com/oauth2/jwks")
                .scope("messages.read")
                .responseType("code")
                .grantType("authorization_code")
                .tokenRevocationEndpoint("https://issuer.example.com/oauth2/revoke")
                .tokenRevocationEndpointAuthenticationMethod("client_secret_basic")
                .tokenIntrospectionEndpoint("https://issuer.example.com/oauth2/introspect")
                .tokenIntrospectionEndpointAuthenticationMethod("client_secret_basic")
                .clientRegistrationEndpoint("https://issuer.example.com/connect/register")
                .codeChallengeMethod("S256")
                .dPoPSigningAlgorithm("ES256")
                .dPoPSigningAlgorithms(algorithms -> algorithms.add("RS256"))
                .claim("service_documentation", "https://issuer.example.com/docs")
                .build();

        assertEquals("https://issuer.example.com", metadata.getIssuer().toExternalForm());
        assertEquals("https://issuer.example.com/oauth2/authorize",
                metadata.getAuthorizationEndpoint().toExternalForm());
        assertEquals("https://issuer.example.com/oauth2/token",
                metadata.getTokenEndpoint().toExternalForm());
        assertEquals(List.of("client_secret_basic"), metadata.getTokenEndpointAuthenticationMethods());
        assertEquals(List.of("messages.read"), metadata.getScopes());
        assertEquals(List.of("code"), metadata.getResponseTypes());
        assertEquals(List.of("authorization_code"), metadata.getGrantTypes());
        assertEquals(List.of("S256"), metadata.getCodeChallengeMethods());
        assertEquals(List.of("ES256", "RS256"), metadata.getDPoPSigningAlgorithms());
        assertEquals("https://issuer.example.com/docs", metadata.<String> getClaim("service_documentation"));
    }

    @Test
    void buildsMetadataFromClaims() {
        OAuth2AuthorizationServerMetadata metadata = OAuth2AuthorizationServerMetadata.withClaims(Map.of(
                OAuth2AuthorizationServerMetadataClaimNames.ISSUER, "https://issuer.example.com",
                OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT,
                "https://issuer.example.com/oauth2/authorize",
                OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT,
                "https://issuer.example.com/oauth2/token",
                OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, List.of("code")))
                .build();

        assertEquals(List.of("code"), metadata.getResponseTypes());
        assertNull(metadata.getGrantTypes());
        assertNull(metadata.getDPoPSigningAlgorithms());
    }

    @Test
    void validatesRequiredAndTypedClaims() {
        IllegalArgumentException missingIssuer = assertThrows(IllegalArgumentException.class,
                () -> OAuth2AuthorizationServerMetadata.builder()
                        .authorizationEndpoint("https://issuer.example.com/oauth2/authorize")
                        .tokenEndpoint("https://issuer.example.com/oauth2/token")
                        .responseType("code")
                        .build());
        assertEquals("issuer cannot be null", missingIssuer.getMessage());

        IllegalArgumentException invalidIssuer = assertThrows(IllegalArgumentException.class,
                () -> minimalBuilder().issuer("not a url").build());
        assertEquals("issuer must be a valid URL", invalidIssuer.getMessage());

        IllegalArgumentException emptyResponseTypes = assertThrows(IllegalArgumentException.class,
                () -> minimalBuilder().responseTypes(List::clear).build());
        assertEquals("responseTypes cannot be empty", emptyResponseTypes.getMessage());

        IllegalArgumentException emptyDpopAlgorithms = assertThrows(IllegalArgumentException.class,
                () -> minimalBuilder().dPoPSigningAlgorithms(List::clear).build());
        assertEquals("dPoPSigningAlgorithms cannot be empty", emptyDpopAlgorithms.getMessage());
    }

    @Test
    void exposesUnmodifiableClaims() {
        OAuth2AuthorizationServerMetadata metadata = minimalBuilder().build();

        assertThrows(UnsupportedOperationException.class,
                () -> metadata.getClaims().put("custom", "value"));
    }

    private static OAuth2AuthorizationServerMetadata.Builder minimalBuilder() {
        return OAuth2AuthorizationServerMetadata.builder()
                .issuer("https://issuer.example.com")
                .authorizationEndpoint("https://issuer.example.com/oauth2/authorize")
                .tokenEndpoint("https://issuer.example.com/oauth2/token")
                .responseType("code");
    }
}

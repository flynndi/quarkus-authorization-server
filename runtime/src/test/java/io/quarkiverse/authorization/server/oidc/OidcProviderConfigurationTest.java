package io.quarkiverse.authorization.server.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class OidcProviderConfigurationTest {

    @Test
    void buildsAndCopiesTypedProviderClaims() {
        OidcProviderConfiguration configuration = builder()
                .scope(OidcScopes.OPENID)
                .userInfoEndpoint("https://issuer.example/userinfo")
                .endSessionEndpoint("https://issuer.example/logout")
                .claim("service_documentation", "https://issuer.example/docs").build();
        OidcProviderConfiguration copy = OidcProviderConfiguration.withClaims(configuration.getClaims()).build();

        assertEquals(configuration.getClaims(), copy.getClaims());
        assertEquals(List.of("public"), copy.getSubjectTypes());
        assertEquals(List.of("RS256"), copy.getIdTokenSigningAlgorithms());
        assertEquals(List.of("openid"), copy.getScopes());
        assertEquals("https://issuer.example/userinfo", copy.getUserInfoEndpoint().toString());
        assertEquals("https://issuer.example/logout", copy.getEndSessionEndpoint().toString());
        assertThrows(UnsupportedOperationException.class, () -> copy.getClaims().clear());
    }

    @Test
    void validatesAllRequiredClaims() {
        for (String claim : List.of("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
                "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported")) {
            assertThrows(IllegalArgumentException.class,
                    () -> builder().claims(claims -> claims.remove(claim)).build(), claim);
        }
        assertThrows(IllegalArgumentException.class, () -> OidcProviderConfiguration.withClaims(Map.of()));
    }

    @Test
    void validatesTypedListsAndOptionalUrls() {
        assertThrows(IllegalArgumentException.class, () -> builder().subjectTypes(List::clear).build());
        assertThrows(IllegalArgumentException.class, () -> builder().idTokenSigningAlgorithms(List::clear).build());
        assertThrows(IllegalArgumentException.class,
                () -> builder().claim("subject_types_supported", "public").build());
        assertThrows(IllegalArgumentException.class,
                () -> builder().claim("id_token_signing_alg_values_supported", "RS256").build());
        assertThrows(IllegalArgumentException.class, () -> builder().jwkSetUrl("not a URL").build());
        assertThrows(IllegalArgumentException.class, () -> builder().userInfoEndpoint("not a URL").build());
        assertThrows(IllegalArgumentException.class, () -> builder().endSessionEndpoint("not a URL").build());
    }

    private static OidcProviderConfiguration.Builder builder() {
        return OidcProviderConfiguration.builder().issuer("https://issuer.example")
                .authorizationEndpoint("https://issuer.example/authorize")
                .tokenEndpoint("https://issuer.example/token").jwkSetUrl("https://issuer.example/jwks")
                .responseType("code").subjectType("public").idTokenSigningAlgorithm("RS256");
    }
}

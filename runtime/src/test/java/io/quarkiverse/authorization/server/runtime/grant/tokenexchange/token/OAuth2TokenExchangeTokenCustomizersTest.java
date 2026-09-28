package io.quarkiverse.authorization.server.runtime.grant.tokenexchange.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.grant.tokenexchange.TokenExchangeRequest;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.runtime.token.DelegatingOAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.JwsHeader;
import io.quarkiverse.authorization.server.token.JwtClaimsSet;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenClaimsSet;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

class OAuth2TokenExchangeTokenCustomizersTest {

    @Test
    void customizesJwtAudienceAndOrderedActorChain() {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder().subject("resource-owner")
                .audience(List.of("exchange-client"));

        OAuth2TokenExchangeTokenCustomizers.jwt()
                .customize(
                        JwtEncodingContext.with(
                                JwsHeader.with(SignatureAlgorithm.RS256.getName()), claims)
                                .principal(delegatedPrincipal())
                                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                                .authorizationGrant(exchangeRequest())
                                .build());

        assertTokenExchangeClaims(claims.build().getClaims());
    }

    @Test
    void customizesOpaqueAudienceAndOrderedActorChain() {
        OAuth2TokenClaimsSet.Builder claims = OAuth2TokenClaimsSet.builder()
                .subject("resource-owner")
                .audience(List.of("exchange-client"));

        OAuth2TokenExchangeTokenCustomizers.accessToken()
                .customize(
                        OAuth2TokenClaimsContext.with(claims)
                                .principal(delegatedPrincipal())
                                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                                .authorizationGrant(exchangeRequest())
                                .build());

        assertTokenExchangeClaims(claims.build().getClaims());
    }

    @Test
    void ignoresOtherGrantTypes() {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder().subject("resource-owner")
                .audience(List.of("password-client"));

        OAuth2TokenExchangeTokenCustomizers.jwt()
                .customize(
                        JwtEncodingContext.with(
                                JwsHeader.with(SignatureAlgorithm.RS256.getName()), claims)
                                .principal(delegatedPrincipal())
                                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                                .build());

        Map<String, Object> result = claims.build().getClaims();
        assertEquals(List.of("password-client"), result.get("aud"));
        assertFalse(result.containsKey("act"));
    }

    @Test
    void delegatesToApplicationCustomizerAfterBuiltInCustomizer() {
        AtomicBoolean observedBuiltInClaims = new AtomicBoolean();
        OAuth2TokenCustomizer<JwtEncodingContext> applicationCustomizer = context -> context.getClaims()
                .claims(
                        claims -> {
                            observedBuiltInClaims.set(
                                    List.of("messages-api", "audit-api")
                                            .equals(claims.get("aud"))
                                            && claims.containsKey("act"));
                            claims.put("aud", List.of("application-override"));
                        });
        DelegatingOAuth2TokenCustomizer<JwtEncodingContext> customizer = new DelegatingOAuth2TokenCustomizer<>(List.of(
                OAuth2TokenExchangeTokenCustomizers.jwt(), applicationCustomizer));
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder().subject("resource-owner")
                .audience(List.of("exchange-client"));

        customizer.customize(
                JwtEncodingContext.with(JwsHeader.with(SignatureAlgorithm.RS256.getName()), claims)
                        .principal(delegatedPrincipal())
                        .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                        .authorizationGrant(exchangeRequest())
                        .build());

        assertTrue(observedBuiltInClaims.get());
        assertEquals(List.of("application-override"), claims.build().getClaim("aud"));
    }

    @SuppressWarnings("unchecked")
    private static void assertTokenExchangeClaims(Map<String, Object> claims) {
        assertEquals(List.of("messages-api", "audit-api"), claims.get("aud"));
        Map<String, Object> currentActor = (Map<String, Object>) claims.get("act");
        assertEquals("current-actor", currentActor.get("sub"));
        assertEquals("https://actor.example", currentActor.get("iss"));
        assertFalse(currentActor.containsKey("exp"));
        Map<String, Object> previousActor = (Map<String, Object>) currentActor.get("act");
        assertEquals(
                Map.of("sub", "previous-actor", "iss", "https://previous.example"), previousActor);
    }

    private static SecurityIdentity delegatedPrincipal() {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal("resource-owner"))
                .addRole("user")
                .addAttribute(
                        OAuth2TokenExchangeTokenCustomizers.ACTORS_ATTRIBUTE,
                        List.of(
                                Map.of(
                                        "sub",
                                        "current-actor",
                                        "iss",
                                        "https://actor.example",
                                        "exp",
                                        12345),
                                Map.of("sub", "previous-actor", "iss", "https://previous.example")))
                .build();
    }

    private static TokenExchangeRequest exchangeRequest() {
        return new TokenExchangeRequest(
                List.of(),
                List.of("messages-api", "audit-api"),
                Set.of("message.read"),
                "urn:ietf:params:oauth:token-type:access_token",
                "subject-token",
                "urn:ietf:params:oauth:token-type:access_token",
                null,
                null,
                QuarkusSecurityIdentity.builder()
                        .setPrincipal(new QuarkusPrincipal("exchange-client"))
                        .addRoles(Set.of())
                        .build(),
                Map.of());
    }
}

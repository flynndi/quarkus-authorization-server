package io.quarkiverse.authorization.server.runtime.dpop;

import static org.junit.jupiter.api.Assertions.*;

import java.time.*;
import java.util.*;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.authentication.OAuth2AuthenticationProviderUtils;
import io.quarkiverse.authorization.server.runtime.client.authentication.OAuth2ClientAuthenticationToken;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.runtime.token.JwtGenerator;
import io.quarkiverse.authorization.server.runtime.token.OAuth2AccessTokenGenerator;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.settings.TokenSettings;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;
import io.quarkiverse.authorization.server.token.ClaimAccessor;
import io.quarkiverse.authorization.server.token.DefaultOAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2RefreshToken;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.runtime.*;

class DPoPTokenBindingTest {
    private static final DPoPProof PROOF = new DPoPProof("a".repeat(43), "proof", Instant.now().plusSeconds(60));

    @Test
    void validatesKeyBeforeAtomicClaimAndRejectsMissingProofForBoundTokens() throws Exception {
        var clock = Clock.fixed(DPoPProofVerifierTest.NOW, ZoneOffset.UTC);
        var binding = new DPoPTokenBinding(
                new DPoPProofVerifier(DPoPProofVerifierTest.config(), clock),
                new InMemoryDPoPReplayStore(1, clock));
        var key = DPoPProofVerifierTest.RSA;
        var request = new DPoPProofRequest(
                DPoPProofVerifierTest.sign(
                        key,
                        DPoPProofVerifierTest.headers(key),
                        DPoPProofVerifierTest.claims()),
                "POST",
                DPoPProofVerifierTest.TOKEN_URI);
        assertNull(binding.verify(null, null));
        assertThrows(OAuth2AuthenticationException.class, () -> binding.verify(null, "bound"));
        assertThrows(OAuth2AuthenticationException.class, () -> binding.verify(request, "wrong"));
        var proof = binding.verify(request, key.calculateBase64urlEncodedThumbprint("SHA-256"));
        binding.claim(request, proof);
        assertThrows(OAuth2AuthenticationException.class, () -> binding.claim(request, proof));
    }

    @Test
    void jwtAndReferenceExposeVerifiedContextAndRetainBindingAfterCustomization() {
        for (var format : List.of(OAuth2TokenFormat.SELF_CONTAINED, OAuth2TokenFormat.REFERENCE)) {
            var context = context(format, true);
            OAuth2Token token;
            if (format.equals(OAuth2TokenFormat.SELF_CONTAINED)) {
                token = new JwtGenerator(
                        keys(),
                        customizer -> {
                            assertSame(PROOF, customizer.get(DPoPProof.class));
                            customizer.getClaims().claim("custom", true);
                        })
                        .generate(context);
            } else {
                var generator = new OAuth2AccessTokenGenerator();
                generator.setAccessTokenCustomizer(
                        customizer -> {
                            assertSame(PROOF, customizer.get(DPoPProof.class));
                            customizer.getClaims().claim("custom", true);
                        });
                token = generator.generate(context);
            }
            var claims = assertInstanceOf(ClaimAccessor.class, token);
            assertEquals(Map.of("jkt", PROOF.jwkThumbprint()), claims.getClaim("cnf"));
            var authorization = OAuth2Authorization.withRegisteredClient(context.getRegisteredClient())
                    .principalName("owner")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
            var access = OAuth2AuthenticationProviderUtils.accessToken(authorization, token, context);
            assertEquals(OAuth2AccessToken.TokenType.DPOP, access.getTokenType());
            assertTrue(DPoPTokenBinding.isBound(authorization.build().getAccessToken()));
        }
    }

    @Test
    void generatorsRejectRemovedOrChangedConfirmationAfterCustomization() {
        for (boolean remove : List.of(true, false)) {
            var jwt = new JwtGenerator(
                    keys(),
                    customizer -> customizer
                            .getClaims()
                            .claims(
                                    claims -> {
                                        if (remove)
                                            claims.remove("cnf");
                                        else
                                            claims.put(
                                                    "cnf",
                                                    Map.of("jkt", "different"));
                                    }));
            assertThrows(
                    OAuth2AuthenticationException.class,
                    () -> jwt.generate(context(OAuth2TokenFormat.SELF_CONTAINED, true)));
            var reference = new OAuth2AccessTokenGenerator();
            reference.setAccessTokenCustomizer(
                    customizer -> customizer
                            .getClaims()
                            .claims(
                                    claims -> {
                                        if (remove)
                                            claims.remove("cnf");
                                        else
                                            claims.put("cnf", Map.of("jkt", "different"));
                                    }));
            assertThrows(
                    OAuth2AuthenticationException.class,
                    () -> reference.generate(context(OAuth2TokenFormat.REFERENCE, true)));
        }
    }

    @Test
    void customGeneratorCannotReturnUnboundTokenForDpopContextOrInventBindingForBearer() {
        var context = context(OAuth2TokenFormat.REFERENCE, true);
        var builder = OAuth2Authorization.withRegisteredClient(context.getRegisteredClient());
        var token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "unbound",
                Instant.now(),
                Instant.now().plusSeconds(60));
        assertThrows(
                OAuth2AuthenticationException.class,
                () -> OAuth2AuthenticationProviderUtils.accessToken(builder, token, context));
        var generator = new OAuth2AccessTokenGenerator();
        generator.setAccessTokenCustomizer(
                c -> c.getClaims().claim("cnf", Map.of("jkt", PROOF.jwkThumbprint())));
        assertThrows(
                OAuth2AuthenticationException.class,
                () -> generator.generate(context(OAuth2TokenFormat.REFERENCE, false)));
        var jwt = new JwtGenerator(
                keys(),
                c -> c.getClaims().claim("cnf", Map.of("jkt", PROOF.jwkThumbprint())));
        assertThrows(
                OAuth2AuthenticationException.class,
                () -> jwt.generate(context(OAuth2TokenFormat.SELF_CONTAINED, false)));
    }

    @Test
    void initialRefreshBindingFollowsActualClientAuthenticationAndReplacesOldMetadata() {
        var client = context(OAuth2TokenFormat.REFERENCE, true).getRegisteredClient();
        var now = Instant.now();
        var token = new OAuth2RefreshToken("refresh", now, now.plusSeconds(300));
        for (var method : List.of(
                ClientAuthenticationMethod.NONE,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            var identity = QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal("client"))
                    .addAttribute(
                            OAuth2ClientAuthenticationToken.CLIENT_AUTHENTICATION_METHOD_ATTRIBUTE,
                            method)
                    .build();
            var authorization = OAuth2Authorization.withRegisteredClient(client)
                    .principalName("owner")
                    .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                    .token(
                            token,
                            metadata -> {
                                metadata.put(
                                        DPoPTokenBinding.REFRESH_JKT_METADATA, "old-key");
                                metadata.put(
                                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                                        true);
                            });
            if (method.equals(ClientAuthenticationMethod.NONE)) {
                var error = assertThrows(
                        OAuth2AuthenticationException.class,
                        () -> DPoPTokenBinding.bindRefreshToken(
                                authorization, token, identity, null));
                assertEquals(OAuth2ErrorCodes.SERVER_ERROR, error.getError().getErrorCode());
            }
            DPoPTokenBinding.bindRefreshToken(authorization, token, identity, PROOF);
            var saved = authorization.build().getRefreshToken();
            assertTrue(saved.isActive());
            assertEquals(
                    method.equals(ClientAuthenticationMethod.NONE) ? PROOF.jwkThumbprint() : null,
                    saved.getMetadata(DPoPTokenBinding.REFRESH_JKT_METADATA));
        }
    }

    private static DefaultOAuth2TokenContext context(OAuth2TokenFormat format, boolean proof) {
        var client = RegisteredClient.withId("client")
                .clientId("client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example/callback")
                .scope("message.read")
                .tokenSettings(TokenSettings.builder().accessTokenFormat(format).build())
                .build();
        var builder = DefaultOAuth2TokenContext.builder()
                .registeredClient(client)
                .principal(
                        QuarkusSecurityIdentity.builder()
                                .setPrincipal(new QuarkusPrincipal("owner"))
                                .build())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(Map.of())
                .authorizedScopes(Set.of("message.read"))
                .authorizationServerContext(
                        new DefaultAuthorizationServerContext(
                                AuthorizationServerSettings.builder()
                                        .issuer("https://issuer.example")
                                        .build()));
        if (proof)
            builder.put(DPoPProof.class, PROOF);
        return builder.build();
    }

    private static AuthorizationServerKeyManager keys() {
        var key = DPoPProofVerifierTest.RSA;
        return new AuthorizationServerKeyManager(
                () -> new AuthorizationServerKeySource.KeySet(
                        List.of(
                                new AuthorizationServerKeySource.Key(
                                        "key",
                                        SignatureAlgorithm.RS256,
                                        key.getPrivateKey(),
                                        key.getPublicKey())),
                        "key"));
    }
}

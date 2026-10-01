package io.quarkiverse.authorization.server.runtime.client.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.DefaultAuthorizationServerContext;
import io.quarkiverse.authorization.server.jose.jws.JwsAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.settings.ClientSettings;

class JwtClientAssertionVerifierTest {
    private static final String ISSUER = "https://issuer.example/tenant/";
    private static final String SECRET = "0123456789abcdef".repeat(4);
    private JwtClientAssertionVerifier verifier = new JwtClientAssertionVerifier(
            new DefaultAuthorizationServerContext(
                    AuthorizationServerSettings.builder().issuer(ISSUER).tokenEndpoint("/token").build()),
            null);
    private ClientJwksTestServer server;
    private final AtomicInteger requests = new AtomicInteger();

    @AfterEach
    void stopServer() throws Exception {
        if (this.server != null)
            this.server.close();
    }

    @ParameterizedTest
    @EnumSource(SignatureAlgorithm.class)
    void verifiesEveryAdvertisedAsymmetricAlgorithmUsingRegisteredJwks(SignatureAlgorithm algorithm) throws Exception {
        PublicJsonWebKey key = switch (algorithm) {
            case ES256 -> EcJwkGenerator.generateJwk(EllipticCurves.P256);
            case ES384 -> EcJwkGenerator.generateJwk(EllipticCurves.P384);
            case ES512 -> EcJwkGenerator.generateJwk(EllipticCurves.P521);
            default -> RsaJwkGenerator.generateJwk(2048);
        };
        key.setKeyId("registered-key");
        String url = this.publish(key);
        RegisteredClient client = JwtClientAssertionVerifierTest.client(algorithm, url);
        String assertion = JwtClientAssertionVerifierTest.sign(
                JwtClientAssertionVerifierTest.claims(), algorithm.getName(), key.getPrivateKey(), key.getKeyId());
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, this.verifier.verify(client, assertion));
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, this.verifier.verify(client, assertion));
        assertEquals(1, this.requests.get(), "JWKS are cached; this verifier does not reject repeated client assertions");
    }

    @Test
    void unknownKidRevalidatesTheProxyCacheAndAuthenticatesWithTheRotatedKey() throws Exception {
        var oldKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        oldKey.setKeyId("old-key");
        var newKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        newKey.setKeyId("new-key");
        AtomicReference<String> originKeys = new AtomicReference<>(
                new JsonWebKeySet(oldKey).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        AtomicReference<String> proxyKeys = new AtomicReference<>(originKeys.get());
        this.server = new ClientJwksTestServer(request -> {
            this.requests.incrementAndGet();
            // A fresh proxy entry is served until the caller explicitly requires revalidation.
            if ("no-cache".equals(request.getHeader("Cache-Control"))) {
                proxyKeys.set(originKeys.get());
            }
            request.response().putHeader("Cache-Control", "max-age=300").end(proxyKeys.get());
        });
        String url = this.server.origin() + "/jwks";
        var cache = this.server.cache(Set.of(this.server.origin()));
        // Exercise key rotation immediately, independently of jose4j's short refresh reprieve.
        cache.get(url).setRefreshReprieveThreshold(0);
        this.verifier = new JwtClientAssertionVerifier(new DefaultAuthorizationServerContext(
                AuthorizationServerSettings.builder().issuer(ISSUER).tokenEndpoint("/token").build()), cache);
        RegisteredClient client = JwtClientAssertionVerifierTest.client(SignatureAlgorithm.ES256, url);
        String initial = JwtClientAssertionVerifierTest.sign(JwtClientAssertionVerifierTest.claims(), "ES256",
                oldKey.getPrivateKey(), oldKey.getKeyId());
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, this.verifier.verify(client, initial));
        originKeys.set(new JsonWebKeySet(newKey).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        String rotated = JwtClientAssertionVerifierTest.sign(JwtClientAssertionVerifierTest.claims(), "ES256",
                newKey.getPrivateKey(), newKey.getKeyId());
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, this.verifier.verify(client, rotated));
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, this.verifier.verify(client, rotated));
        assertEquals(2, this.requests.get(), "Initial download and one refresh; the rotated keys are cached locally");
    }

    @ParameterizedTest
    @EnumSource(MacAlgorithm.class)
    void verifiesEveryAdvertisedMacAlgorithmWithoutRequiringIatOrJti(MacAlgorithm algorithm) throws Exception {
        RegisteredClient client = JwtClientAssertionVerifierTest.client(algorithm, null);
        String assertion = JwtClientAssertionVerifierTest.sign(
                JwtClientAssertionVerifierTest.claims(), algorithm.getName(),
                new HmacKey(SECRET.getBytes(StandardCharsets.UTF_8)), null);
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT, this.verifier.verify(client, assertion));
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT, this.verifier.verify(client, assertion));
    }

    @ParameterizedTest
    @ValueSource(strings = { ISSUER, "https://issuer.example/tenant/token", "https://issuer.example/tenant/oauth2/introspect",
            "https://issuer.example/tenant/oauth2/revoke" })
    void acceptsIssuerOrInstalledEndpointAudiences(String audience) throws Exception {
        JwtClaims claims = JwtClientAssertionVerifierTest.claims();
        claims.setAudience("unrelated-audience", audience);
        String assertion = JwtClientAssertionVerifierTest.sign(claims, "HS256",
                new HmacKey(SECRET.getBytes(StandardCharsets.UTF_8)), null);
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT,
                this.verifier.verify(JwtClientAssertionVerifierTest.client(MacAlgorithm.HS256, null), assertion));
    }

    @Test
    void rejectsMissingWrongMalformedAndExpiredClaims() throws Exception {
        for (String claim : List.of("iss", "sub", "aud", "exp")) {
            JwtClaims claims = JwtClientAssertionVerifierTest.claims();
            claims.unsetClaim(claim);
            this.assertInvalidClaims(claims);
        }
        for (String claim : List.of("iss", "sub", "aud")) {
            JwtClaims claims = JwtClientAssertionVerifierTest.claims();
            claims.setClaim(claim, "different-client-or-server");
            this.assertInvalidClaims(claims);
        }
        for (String claim : List.of("exp", "nbf")) {
            JwtClaims claims = JwtClientAssertionVerifierTest.claims();
            claims.setClaim(claim, "not-a-numeric-date");
            this.assertInvalidClaims(claims);
        }
        JwtClaims expired = JwtClientAssertionVerifierTest.claims();
        expired.setClaim("exp", Instant.now().minusSeconds(120).getEpochSecond());
        this.assertInvalidClaims(expired);
        JwtClaims future = JwtClientAssertionVerifierTest.claims();
        future.setClaim("nbf", Instant.now().plusSeconds(120).getEpochSecond());
        this.assertInvalidClaims(future);
    }

    @Test
    void rejectsWrongKeyAlgorithmMethodMissingSettingsAndExpiredSharedSecret() throws Exception {
        RegisteredClient client = JwtClientAssertionVerifierTest.client(MacAlgorithm.HS256, null);
        String valid = JwtClientAssertionVerifierTest.sign(JwtClientAssertionVerifierTest.claims(), "HS256",
                new HmacKey(SECRET.getBytes(StandardCharsets.UTF_8)), null);
        this.assertInvalid(client, JwtClientAssertionVerifierTest.sign(JwtClientAssertionVerifierTest.claims(), "HS256",
                new HmacKey("wrong-secret".repeat(8).getBytes(StandardCharsets.UTF_8)), null));
        this.assertInvalid(client, JwtClientAssertionVerifierTest.sign(JwtClientAssertionVerifierTest.claims(), "HS384",
                new HmacKey(SECRET.getBytes(StandardCharsets.UTF_8)), null));
        this.assertInvalid(RegisteredClient.from(client).clientSettings(ClientSettings.builder().build()).build(), valid);
        this.assertInvalid(RegisteredClient.from(client).clientSecretExpiresAt(Instant.now().minusSeconds(1)).build(), valid);
        this.assertInvalid(RegisteredClient.from(client).clientSecret(null).build(), valid);
        this.assertInvalid(RegisteredClient.withId("wrong-method").clientId(client.getClientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(client.getClientSettings()).build(), valid);
        for (String malformed : List.of("not-a-jwt", "a.b.", "a.b.c.d.e", "x".repeat(16_385))) {
            this.assertInvalid(client, malformed);
        }
    }

    @Test
    void doesNotTrustEmbeddedKeysOrAllowHmacWithAnRsaPublicKey() throws Exception {
        PublicJsonWebKey registered = RsaJwkGenerator.generateJwk(2048);
        registered.setKeyId("trusted");
        PublicJsonWebKey attacker = RsaJwkGenerator.generateJwk(2048);
        RegisteredClient client = JwtClientAssertionVerifierTest.client(SignatureAlgorithm.RS256, this.publish(registered));
        JsonWebSignature forged = new JsonWebSignature();
        forged.setPayload(JwtClientAssertionVerifierTest.claims().toJson());
        forged.setAlgorithmHeaderValue("RS256");
        forged.setKeyIdHeaderValue("trusted");
        forged.setJwkHeader(attacker);
        forged.setKey(attacker.getPrivateKey());
        this.assertInvalid(client, forged.getCompactSerialization());
        this.assertInvalid(client, JwtClientAssertionVerifierTest.sign(JwtClientAssertionVerifierTest.claims(), "HS256",
                new HmacKey(registered.getPublicKey().getEncoded()), "trusted"));
        this.assertInvalid(client, JwtClientAssertionVerifierTest.sign(JwtClientAssertionVerifierTest.claims(), "RS256",
                registered.getPrivateKey(), "unknown-key"));
    }

    @Test
    void rejectsWeakHmacKeysEvenWhenAnAttackerSignsWithoutKeyValidation() throws Exception {
        JsonWebSignature assertion = new JsonWebSignature();
        assertion.setDoKeyValidation(false);
        assertion.setAlgorithmHeaderValue("HS256");
        assertion.setPayload(JwtClientAssertionVerifierTest.claims().toJson());
        assertion.setKey(new HmacKey("short".getBytes(StandardCharsets.UTF_8)));
        this.assertInvalid(RegisteredClient.from(JwtClientAssertionVerifierTest.client(MacAlgorithm.HS256, null))
                .clientSecret("short").build(), assertion.getCompactSerialization());
    }

    @Test
    void appliesTimestampToleranceWithoutAddingARequiredIssuedAt() throws Exception {
        JwtClaims claims = JwtClientAssertionVerifierTest.claims();
        claims.setClaim("exp", Instant.now().minusSeconds(30).getEpochSecond());
        String assertion = JwtClientAssertionVerifierTest.sign(claims, "HS256",
                new HmacKey(SECRET.getBytes(StandardCharsets.UTF_8)), null);
        assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT,
                this.verifier.verify(JwtClientAssertionVerifierTest.client(MacAlgorithm.HS256, null), assertion));
    }

    private void assertInvalidClaims(JwtClaims claims) throws Exception {
        this.assertInvalid(JwtClientAssertionVerifierTest.client(MacAlgorithm.HS256, null),
                JwtClientAssertionVerifierTest.sign(claims, "HS256", new HmacKey(SECRET.getBytes(StandardCharsets.UTF_8)),
                        null));
    }

    private void assertInvalid(RegisteredClient client, String assertion) {
        var error = assertThrows(OAuth2AuthenticationException.class, () -> this.verifier.verify(client, assertion));
        assertEquals("invalid_client", error.getError().getErrorCode());
        assertNull(error.getCause());
        assertNull(error.getError().getDescription());
    }

    private String publish(PublicJsonWebKey key) throws Exception {
        byte[] json = new JsonWebKeySet(key).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY).getBytes(StandardCharsets.UTF_8);
        this.server = new ClientJwksTestServer(request -> {
            this.requests.incrementAndGet();
            request.response().putHeader("Cache-Control", "max-age=300").end(io.vertx.core.buffer.Buffer.buffer(json));
        });
        this.verifier = new JwtClientAssertionVerifier(new DefaultAuthorizationServerContext(
                AuthorizationServerSettings.builder().issuer(ISSUER).tokenEndpoint("/token").build()),
                this.server.cache(java.util.Set.of(this.server.origin())));
        return this.server.origin() + "/jwks";
    }

    private static RegisteredClient client(JwsAlgorithm algorithm, String url) {
        ClientSettings.Builder settings = ClientSettings.builder().tokenEndpointAuthenticationSigningAlgorithm(algorithm);
        if (url != null)
            settings.jwkSetUrl(url);
        return RegisteredClient.withId("registration").clientId("jwt-client").clientSecret(SECRET)
                .clientAuthenticationMethod(algorithm instanceof MacAlgorithm
                        ? ClientAuthenticationMethod.CLIENT_SECRET_JWT
                        : ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).clientSettings(settings.build()).build();
    }

    private static JwtClaims claims() {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("jwt-client");
        claims.setSubject("jwt-client");
        claims.setAudience(ISSUER);
        claims.setExpirationTimeMinutesInTheFuture(5);
        return claims;
    }

    private static String sign(JwtClaims claims, String algorithm, Key key, String kid) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(algorithm);
        if (kid != null)
            jws.setKeyIdHeaderValue(kid);
        jws.setPayload(claims.toJson());
        jws.setKey(key);
        return jws.getCompactSerialization();
    }
}

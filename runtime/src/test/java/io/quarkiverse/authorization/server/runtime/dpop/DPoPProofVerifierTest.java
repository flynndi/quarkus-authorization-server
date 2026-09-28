package io.quarkiverse.authorization.server.runtime.dpop;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.*;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig.DPoPConfig;

class DPoPProofVerifierTest {
    static final Instant NOW = Instant.parse("2026-09-08T00:00:00Z");
    static final URI TOKEN_URI = URI.create("https://server.example/oauth2/token");
    static final PublicJsonWebKey RSA;

    static {
        try {
            RSA = RsaJwkGenerator.generateJwk(2048);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private final DPoPProofVerifier verifier = new DPoPProofVerifier(config(), Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void acceptsRsaAndEcAndReturnsOnlyBindingAndReplayData() throws Exception {
        for (var key : List.of(RSA, EcJwkGenerator.generateJwk(EllipticCurves.P256))) {
            DPoPProof proof = verifier.verify(request(sign(key, headers(key), claims())));
            assertEquals(key.calculateBase64urlEncodedThumbprint("SHA-256"), proof.jwkThumbprint());
            assertEquals("proof-id", proof.jwtId());
            assertEquals(NOW.plusSeconds(60), proof.expiresAt());
        }
    }

    @Test
    void normalizesUriWithoutBindingQueryParameters() throws Exception {
        Map<String, Object> claims = claims();
        claims.put("htu", "https://SERVER.example:443/a/../oauth2/%74oken");
        DPoPProofRequest request = new DPoPProofRequest(
                sign(RSA, headers(RSA), claims),
                "POST",
                URI.create("https://server.example/oauth2/token?ignored=true"));
        assertNotNull(verifier.verify(request));
        assertFalse(request.toString().contains(request.proof()));
        claims.put("htu", "https://server.example/oauth2%2Ftoken");
        rejects(sign(RSA, headers(RSA), claims));
    }

    @Test
    void preservesEmptyPathSegmentsWhenRemovingDotSegments() throws Exception {
        for (var entry : Map.of(
                "/a//b", "/a//b",
                "/a//../b", "/a/b",
                "/a/%2e%2e//b/.", "//b/",
                "/../../a/b/..", "/a/",
                "/a/../..", "/")
                .entrySet()) {
            assertEquals(
                    URI.create("https://server.example" + entry.getValue()),
                    DPoPProofRequest.canonicalUri(
                            URI.create("https://server.example" + entry.getKey())));
        }
        var claims = claims();
        claims.put("htu", "https://server.example/oauth2//token");
        String proof = sign(RSA, headers(RSA), claims);
        rejects(proof);
        assertNotNull(
                verifier.verify(
                        new DPoPProofRequest(
                                proof,
                                "POST",
                                URI.create("https://server.example/oauth2//token"))));
    }

    @Test
    void rejectsWrongMethodUriAndNoncanonicalProofTargets() throws Exception {
        for (String uri : List.of(
                "https://other.example/oauth2/token",
                "https://server.example/other",
                "https://server.example/oauth2/token?query=1",
                "https://server.example/oauth2/token#fragment",
                "/oauth2/token",
                "https://user@server.example/oauth2/token")) {
            var claims = claims();
            claims.put("htu", uri);
            rejects(sign(RSA, headers(RSA), claims));
        }
        var claims = claims();
        claims.put("htm", "GET");
        rejects(sign(RSA, headers(RSA), claims));
        claims.put("htm", "post");
        rejects(sign(RSA, headers(RSA), claims));
        claims.remove("htm");
        rejects(sign(RSA, headers(RSA), claims));
    }

    @Test
    void rejectsWrongSignaturePrivateSymmetricOrMissingJwkAndUnexpectedType() throws Exception {
        var other = RsaJwkGenerator.generateJwk(2048);
        rejects(sign(other, headers(RSA), claims()));
        for (Object jwk : List.of(
                RSA.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE),
                Map.of("kty", "oct", "k", "c2VjcmV0"),
                "not-an-object",
                Map.of("kty", "RSA"))) {
            var headers = headers(RSA);
            headers.put("jwk", jwk);
            rejects(sign(RSA, headers, claims()));
        }
        var headers = headers(RSA);
        headers.remove("jwk");
        rejects(sign(RSA, headers, claims()));
        headers = headers(RSA);
        headers.put("typ", "JWT");
        rejects(sign(RSA, headers, claims()));
        headers = headers(RSA);
        headers.put("crit", List.of("custom"));
        rejects(sign(RSA, headers, claims()));
    }

    @Test
    void rejectsUnsupportedAlgorithmCompactAndDuplicateJsonMembers() throws Exception {
        var headers = headers(RSA);
        headers.put("alg", "RS512");
        rejects(sign(RSA, headers, claims()));
        for (String proof : List.of("", "a.b", "a.b.c.d.e", "a.b.c", "x".repeat(16385)))
            rejects(proof);
        String jwt = sign(RSA, headers(RSA), claims());
        String payload = JsonUtil.toJson(claims());
        JsonWebSignature jws = new JsonWebSignature();
        headers(RSA).forEach(jws::setHeader);
        jws.setPayload(payload.substring(0, payload.length() - 1) + ",\"jti\":\"duplicate\"}");
        jws.setKey(RSA.getPrivateKey());
        rejects(jws.getCompactSerialization());
        rejects(jwt.substring(0, jwt.lastIndexOf('.') + 1));
    }

    @Test
    void checksRequiredReplayClaimsAndExclusiveExpiry() throws Exception {
        for (Object iat : List.of(
                NOW.getEpochSecond() - 60,
                NOW.getEpochSecond() + 6,
                "123",
                true,
                List.of(1),
                Double.POSITIVE_INFINITY)) {
            var claims = claims();
            claims.put("iat", iat);
            assertThrows(
                    OAuth2AuthenticationException.class,
                    () -> verifier.validateReplayClaims(thumbprint(), claims));
        }
        for (String name : List.of("iat", "jti")) {
            var claims = claims();
            claims.remove(name);
            rejects(sign(RSA, headers(RSA), claims));
        }
        for (Object id : List.of("", " ", "a".repeat(257), 123)) {
            var claims = claims();
            claims.put("jti", id);
            rejects(sign(RSA, headers(RSA), claims));
        }
        var claims = claims();
        claims.put("iat", NOW.getEpochSecond() + 5);
        assertEquals(
                NOW.plusSeconds(65),
                verifier.verify(request(sign(RSA, headers(RSA), claims))).expiresAt());
        claims.put("iat", NOW.getEpochSecond() + 0.5);
        assertEquals(
                NOW.plusSeconds(60).plusMillis(500),
                verifier.verify(request(sign(RSA, headers(RSA), claims))).expiresAt());
    }

    @Test
    void verificationDoesNotConsumeProofBeforeCallerChecksGrantBinding() throws Exception {
        var request = request(sign(RSA, headers(RSA), claims()));
        assertEquals(verifier.verify(request), verifier.verify(request));
    }

    @Test
    void resourceProofRequiresExactUnpaddedSha256AccessTokenHash() throws Exception {
        var claims = claims();
        String token = "opaque-access-token";
        String hash = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                        MessageDigest.getInstance("SHA-256")
                                .digest(token.getBytes(StandardCharsets.US_ASCII)));
        claims.put("ath", hash);
        var request = request(sign(RSA, headers(RSA), claims));
        assertNotNull(verifier.verify(request, token));
        assertThrows(
                OAuth2AuthenticationException.class, () -> verifier.verify(request, "other-token"));
        for (Object invalid : List.of("", hash + "=", "different", 123, List.of(hash))) {
            claims.put("ath", invalid);
            var invalidRequest = request(sign(RSA, headers(RSA), claims));
            var error = assertThrows(
                    OAuth2AuthenticationException.class,
                    () -> verifier.verify(invalidRequest, token));
            assertEquals("invalid_dpop_proof", error.getError().getErrorCode());
        }
    }

    @Test
    void tokenEndpointProofDoesNotSatisfyResourceAccessWithoutAth() throws Exception {
        var request = request(sign(RSA, headers(RSA), claims()));
        assertNotNull(verifier.verify(request));
        assertThrows(OAuth2AuthenticationException.class, () -> verifier.verify(request, "access"));
    }

    private void rejects(String proof) {
        var error = assertThrows(
                OAuth2AuthenticationException.class, () -> verifier.verify(request(proof)));
        assertEquals("invalid_dpop_proof", error.getError().getErrorCode());
        assertNull(error.getCause());
    }

    static DPoPProofRequest request(String proof) {
        return new DPoPProofRequest(proof, "POST", TOKEN_URI);
    }

    static String thumbprint() {
        try {
            return RSA.calculateBase64urlEncodedThumbprint("SHA-256");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static Map<String, Object> claims() {
        return new LinkedHashMap<>(
                Map.of(
                        "jti",
                        "proof-id",
                        "iat",
                        NOW.getEpochSecond(),
                        "htm",
                        "POST",
                        "htu",
                        TOKEN_URI.toString()));
    }

    static Map<String, Object> headers(PublicJsonWebKey key) {
        return new LinkedHashMap<>(
                Map.of(
                        "typ",
                        "dpop+jwt",
                        "alg",
                        key instanceof RsaJsonWebKey ? "RS256" : "ES256",
                        "jwk",
                        key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
    }

    static String sign(
            PublicJsonWebKey key, Map<String, Object> headers, Map<String, Object> claims)
            throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        headers.forEach(jws::setHeader);
        jws.setPayload(JsonUtil.toJson(claims));
        jws.setKey(key.getPrivateKey());
        return jws.getCompactSerialization();
    }

    static DPoPConfig config() {
        return new DPoPConfig() {
            public Set<SignatureAlgorithm> proofAlgorithms() {
                return Set.of(SignatureAlgorithm.ES256, SignatureAlgorithm.RS256);
            }

            public Duration proofMaxAge() {
                return Duration.ofSeconds(60);
            }

            public Duration clockSkew() {
                return Duration.ofSeconds(5);
            }

            public int maxProofLength() {
                return 16384;
            }

            public int replayCacheSize() {
                return 100000;
            }
        };
    }
}

package io.quarkiverse.authorization.server.deployment;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.inject.Inject;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofVerifier;
import io.quarkus.test.QuarkusUnitTest;

class DPoPMetadataTest {
    private static final URI TOKEN_URI = URI.create("https://issuer.example/oauth2/token");

    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource("privateKey.pem").addAsResource("publicKey.pem"))
            .overrideConfigKey("quarkus.authorization-server.issuer", "https://issuer.example")
            .overrideConfigKey("quarkus.authorization-server.oidc.enabled", "true")
            .overrideConfigKey("quarkus.authorization-server.signing.key-id", "test-key")
            .overrideConfigKey("quarkus.authorization-server.signing.private-key-location", "classpath:privateKey.pem")
            .overrideConfigKey("quarkus.authorization-server.signing.public-key-location", "classpath:publicKey.pem")
            .overrideConfigKey("quarkus.authorization-server.dpop.proof-algorithms", "PS256,ES384");

    @Inject
    DPoPProofVerifier verifier;

    @Test
    void bothEndpointsUseConfiguredProofAlgorithmsIndependentlyOfServerSigningKeys() {
        for (String path : List.of(
                "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
            given().get(path).then().statusCode(200)
                    .body("dpop_signing_alg_values_supported", contains("ES384", "PS256"));
        }
        given().get("/.well-known/openid-configuration").then().statusCode(200)
                .body("id_token_signing_alg_values_supported", contains("RS256"));
    }

    @Test
    void verifierAcceptsAdvertisedAlgorithmsAndRejectsRemovedDefaults() throws Exception {
        var rsa = RsaJwkGenerator.generateJwk(2048);
        assertNotNull(verifier.verify(proof(EcJwkGenerator.generateJwk(EllipticCurves.P384), "ES384")));
        assertNotNull(verifier.verify(proof(rsa, "PS256")));
        for (var entry : Map.of("ES256", EcJwkGenerator.generateJwk(EllipticCurves.P256),
                "RS256", rsa).entrySet()) {
            var request = proof(entry.getValue(), entry.getKey());
            var failure = assertThrows(OAuth2AuthenticationException.class, () -> verifier.verify(request));
            assertEquals("invalid_dpop_proof", failure.getError().getErrorCode());
        }
    }

    private static DPoPProofRequest proof(PublicJsonWebKey key, String algorithm) throws Exception {
        var jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(algorithm);
        jws.setHeader("typ", "dpop+jwt");
        jws.setJwkHeader(key);
        jws.setPayload(JsonUtil.toJson(Map.of(
                "htm", "POST", "htu", TOKEN_URI.toString(),
                "iat", Instant.now().getEpochSecond(), "jti", UUID.randomUUID().toString())));
        jws.setKey(key.getPrivateKey());
        return new DPoPProofRequest(jws.getCompactSerialization(), "POST", TOKEN_URI);
    }
}

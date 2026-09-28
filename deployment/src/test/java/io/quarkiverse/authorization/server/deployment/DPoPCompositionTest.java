package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.dpop.DPoPReplayStore;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofVerifier;
import io.quarkus.test.QuarkusUnitTest;

class DPoPCompositionTest {
    @RegisterExtension
    static final QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClass(ApplicationReplayStore.class))
            .overrideConfigKey(
                    "quarkus.authorization-server.issuer", "https://issuer.example");

    @Inject
    DPoPReplayStore replay;
    @Inject
    DPoPProofVerifier verifier;
    @Inject
    AuthorizationServerRuntimeConfig config;

    @Test
    void applicationReplayStoreReplacesTheDefaultWithoutQualifiersOrProducers() {
        assertInstanceOf(ApplicationReplayStore.class, replay);
        assertNotNull(verifier);
        assertFalse(
                replay.claim(
                        new DPoPReplayStore.Key(
                                URI.create("https://issuer.example/oauth2/token"), "key", "id"),
                        Instant.now().plusSeconds(60)));
    }

    @Test
    void mapsBoundedProofDefaultsFromQuarkusConfig() {
        assertEquals(
                Set.of(SignatureAlgorithm.ES256, SignatureAlgorithm.RS256),
                config.dpop().proofAlgorithms());
        assertEquals(Duration.ofMinutes(1), config.dpop().proofMaxAge());
        assertEquals(Duration.ofSeconds(5), config.dpop().clockSkew());
        assertEquals(16384, config.dpop().maxProofLength());
        assertEquals(100000, config.dpop().replayCacheSize());
    }

    @Singleton
    public static class ApplicationReplayStore implements DPoPReplayStore {
        @Override
        public boolean claim(Key key, Instant expiresAt) {
            return false;
        }
    }
}

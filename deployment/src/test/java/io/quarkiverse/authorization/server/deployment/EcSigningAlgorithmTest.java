package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Set;

import jakarta.inject.Inject;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkus.test.QuarkusUnitTest;

class EcSigningAlgorithmTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addClasses(NativeImageResourceAssertions.class,
                    NativeImageResourceAssertions.ResourcesVerifiedBuildItem.class)
                    .addAsResource("ecPrivateKey.pem")
                    .addAsResource("ecPublicKey.pem")
                    .addAsResource(new StringAsset("""
                            quarkus.authorization-server.issuer=https://issuer.example.com
                            quarkus.authorization-server.signing.algorithm=ES256
                            quarkus.authorization-server.signing.key-id=ec-key
                            quarkus.authorization-server.signing.private-key-location=classpath:ecPrivateKey.pem
                            quarkus.authorization-server.signing.public-key-location=classpath:ecPublicKey.pem
                            """), "application.properties"))
            .addBuildChainCustomizer(
                    NativeImageResourceAssertions.verify(Set.of("ecPrivateKey.pem", "ecPublicKey.pem"), Set.of()));

    @Inject
    AuthorizationServerKeyManager keyManager;

    @Test
    void loadsEcKeyAndPublishesEcJwk() {
        assertEquals(SignatureAlgorithm.ES256, this.keyManager.getAlgorithm());
        assertEquals("EC", this.keyManager.getPublicJwks().getFirst().get("kty"));
        assertEquals("P-256", this.keyManager.getPublicJwks().getFirst().get("crv"));
        assertEquals("ES256", this.keyManager.getPublicJwks().getFirst().get("alg"));
    }
}

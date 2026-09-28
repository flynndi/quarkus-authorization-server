package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class OidcSigningConfigurationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar.addAsResource("ecPrivateKey.pem").addAsResource("ecPublicKey.pem")
                    .addAsResource("publicKey.pem")
                    .addAsResource(new StringAsset("""
                            quarkus.authorization-server.issuer=https://issuer.example
                            quarkus.authorization-server.oidc.enabled=true
                            quarkus.authorization-server.signing.active-key-id=ec
                            quarkus.authorization-server.signing.keys.ec.algorithm=ES256
                            quarkus.authorization-server.signing.keys.ec.private-key-location=classpath:ecPrivateKey.pem
                            quarkus.authorization-server.signing.keys.ec.public-key-location=classpath:ecPublicKey.pem
                            quarkus.authorization-server.signing.keys.rs.algorithm=RS256
                            quarkus.authorization-server.signing.keys.rs.public-key-location=classpath:publicKey.pem
                            """), "application.properties"))
            .assertException(failure -> {
                boolean found = false;
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    found |= cause.getMessage() != null
                            && cause.getMessage().contains("OpenID Connect requires an RS256 signing private key");
                }
                assertTrue(found, failure.toString());
            });

    @Test
    void rejectsVerificationOnlyRs256KeyInsteadOfAdvertisingAnUnavailableAlgorithm() {
    }
}

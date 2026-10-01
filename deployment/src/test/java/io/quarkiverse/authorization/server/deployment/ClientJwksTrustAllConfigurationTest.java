package io.quarkiverse.authorization.server.deployment;

import static org.junit.jupiter.api.Assertions.fail;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

class ClientJwksTrustAllConfigurationTest {
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            // Validation must not depend on authentication providers eagerly creating the JWKS client.
            .overrideConfigKey("quarkus.arc.exclude-types",
                    "io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionAuthenticationProvider,"
                            + "io.quarkiverse.authorization.server.runtime.client.authentication.X509ClientCertificateAuthenticationProvider")
            .withApplicationRoot(jar -> jar
                    .addAsResource("privateKey.pem").addAsResource("publicKey.pem")
                    .addAsResource(new StringAsset("""
                            quarkus.authorization-server.issuer=https://issuer.example.com
                            quarkus.authorization-server.signing.key-id=jwks-test-key
                            quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                            quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                            quarkus.authorization-server.client-jwks.tls-configuration-name=unsafe-jwks
                            quarkus.tls.unsafe-jwks.trust-all=true
                            """), "application.properties"))
            .assertException(failure -> {
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    if (cause instanceof IllegalArgumentException && cause.getMessage() != null
                            && cause.getMessage().contains("quarkus.tls.unsafe-jwks.trust-all=true")) {
                        return;
                    }
                }
                fail("Expected the selected trust-all TLS configuration to be rejected", failure);
            });

    @Test
    void rejectsNamedTrustAllConfigurationBeforeCreatingTheJwksClient() {
        fail("The application must reject an unsafe client JWKS TLS configuration during startup");
    }
}

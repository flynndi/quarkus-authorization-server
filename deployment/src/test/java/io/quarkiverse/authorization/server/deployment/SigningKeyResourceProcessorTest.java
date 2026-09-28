package io.quarkiverse.authorization.server.deployment;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.smallrye.config.EnvConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

class SigningKeyResourceProcessorTest {
    @Test
    void readsSingleKeyLocationsProvidedOnlyByBuildTimeEnvironmentVariables() {
        SmallRyeConfig config = new SmallRyeConfigBuilder().withSources(new EnvConfigSource(Map.of(
                "QUARKUS_AUTHORIZATION_SERVER_SIGNING_PRIVATE_KEY_LOCATION", "classpath:env-private.pem",
                "QUARKUS_AUTHORIZATION_SERVER_SIGNING_PUBLIC_KEY_LOCATION", "classpath:env-public.pem"), 300)).build();
        Assertions.assertEquals(Set.of("env-private.pem", "env-public.pem"),
                SigningKeyResourceProcessor.classpathResources(config));
    }

    @Test
    void includesOnlyClasspathLocationsAndNormalizesTheLeadingSlash() {
        SmallRyeConfig config = new SmallRyeConfigBuilder()
                .withDefaultValue("quarkus.authorization-server.signing.private-key-location", "classpath:/keys/private.pem")
                .withDefaultValue("quarkus.authorization-server.signing.public-key-location", "classpath:keys/public.pem")
                .build();
        Assertions.assertEquals(Set.of("keys/private.pem", "keys/public.pem"),
                SigningKeyResourceProcessor.classpathResources(config));
    }

    @Test
    void handlesQuotedRotationKeyIdsAndDeduplicatesResources() {
        SmallRyeConfig config = new SmallRyeConfigBuilder()
                .withDefaultValue("quarkus.authorization-server.signing.keys.\"current.v2\".private-key-location",
                        "classpath:current.pem")
                .withDefaultValue("quarkus.authorization-server.signing.keys.\"current.v2\".public-key-location",
                        "classpath:shared-public.pem")
                .withDefaultValue("quarkus.authorization-server.signing.keys.previous.public-key-location",
                        "classpath:/shared-public.pem")
                .build();
        Assertions.assertEquals(Set.of("current.pem", "shared-public.pem"),
                SigningKeyResourceProcessor.classpathResources(config));
    }

    @Test
    void excludesFilesystemPathsEmptyLocationsAndUnrelatedProperties() {
        SmallRyeConfig config = new SmallRyeConfigBuilder()
                .withDefaultValue("quarkus.authorization-server.signing.private-key-location", "file:/run/secrets/private.pem")
                .withDefaultValue("quarkus.authorization-server.signing.public-key-location", "keys/public.pem")
                .withDefaultValue("quarkus.authorization-server.signing.keys.external.public-key-location", "/run/public.pem")
                .withDefaultValue("quarkus.authorization-server.signing.keys.empty.private-key-location", "classpath:")
                .withDefaultValue("quarkus.authorization-server.signing.keys.empty.public-key-location", "classpath:/")
                .withDefaultValue("quarkus.authorization-server.signing.key-id", "classpath:not-a-location")
                .withDefaultValue("quarkus.authorization-server.signing.keys.key.nested.public-key-location",
                        "classpath:invalid")
                .withDefaultValue("quarkus.authorization-server.signing-extra.public-key-location", "classpath:unrelated")
                .build();
        Assertions.assertEquals(Set.of(), SigningKeyResourceProcessor.classpathResources(config));
    }

    @Test
    void usesTheActiveProfileAndResolvedExpressions() {
        SmallRyeConfig config = new SmallRyeConfigBuilder().addDefaultInterceptors().withProfile("test")
                .withDefaultValue("demo.key", "classpath:test.pem")
                .withDefaultValue("quarkus.authorization-server.signing.private-key-location", "classpath:prod.pem")
                .withDefaultValue("%test.quarkus.authorization-server.signing.private-key-location", "${demo.key}")
                .withDefaultValue("%other.quarkus.authorization-server.signing.keys.old.public-key-location",
                        "classpath:other.pem")
                .build();
        Assertions.assertEquals(Set.of("test.pem"), SigningKeyResourceProcessor.classpathResources(config));
    }

    @Test
    void leavesUnresolvedRuntimeExpressionsToTheRuntimeConfiguration() {
        SmallRyeConfig config = new SmallRyeConfigBuilder().addDefaultInterceptors()
                .withDefaultValue("quarkus.authorization-server.signing.private-key-location", "${runtime.private-key}")
                .withDefaultValue("quarkus.authorization-server.signing.public-key-location", "classpath:${runtime.public-key}")
                .build();
        Assertions.assertEquals(Set.of(), SigningKeyResourceProcessor.classpathResources(config));
    }
}

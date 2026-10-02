package io.quarkiverse.authorization.server.deployment;

import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkus.builder.BuildChainBuilder;
import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.test.QuarkusUnitTest;

class AuthorizationServerJdbcNativeImageRegistrationTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withEmptyApplication()
            .addBuildChainCustomizer(verifyJdbcNativeImageRegistrations());

    @Test
    void augmentsApplicationWithJdbcNativeImageRegistrations() {
    }

    private static Consumer<BuildChainBuilder> verifyJdbcNativeImageRegistrations() {
        return builder -> {
            builder.addBuildStep(
                    context -> {
                        Set<String> resources = context
                                .consumeMulti(NativeImageResourceBuildItem.class)
                                .stream()
                                .flatMap(item -> item.getResources().stream())
                                .collect(Collectors.toSet());
                        Set<String> expectedResources = Set.of(
                                JdbcRegisteredClientRepository.SCHEMA_LOCATION,
                                JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION,
                                JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
                        if (!resources.containsAll(expectedResources)) {
                            throw new IllegalStateException(
                                    "Missing JDBC native-image resources: "
                                            + expectedResources);
                        }

                        boolean legacyBindingRegistered = context.consumeMulti(ReflectiveClassBuildItem.class).stream()
                                .flatMap(item -> item.getClassNames().stream())
                                .anyMatch(name -> name.startsWith("io.quarkiverse.authorization.server.runtime.jackson2."));
                        if (legacyBindingRegistered) {
                            throw new IllegalStateException("Legacy JDBC Jackson reflection registration remains");
                        }

                        context.produce(
                                new JdbcNativeImageRegistrationsVerifiedBuildItem());
                    })
                    .consumes(NativeImageResourceBuildItem.class)
                    .consumes(ReflectiveClassBuildItem.class)
                    .produces(JdbcNativeImageRegistrationsVerifiedBuildItem.class)
                    .build();
            builder.addFinal(JdbcNativeImageRegistrationsVerifiedBuildItem.class);
        };
    }

    static final class JdbcNativeImageRegistrationsVerifiedBuildItem extends SimpleBuildItem {
    }
}

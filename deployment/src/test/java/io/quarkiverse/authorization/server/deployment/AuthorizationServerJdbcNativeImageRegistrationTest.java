package io.quarkiverse.authorization.server.deployment;

import java.security.Principal;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationResponseType;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.runtime.jackson2.SecurityIdentityAttributesConverter;
import io.quarkiverse.authorization.server.runtime.jackson2.SecurityIdentityJacksonBuilder;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.builder.BuildChainBuilder;
import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
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

                        Set<String> expectedTypes = Set.of(
                                QuarkusSecurityIdentity.class.getName(),
                                QuarkusPrincipal.class.getName(),
                                Principal.class.getName(),
                                SecurityIdentityJacksonBuilder.class.getName(),
                                SecurityIdentityAttributesConverter.class.getName(),
                                OAuth2AuthorizationRequest.class.getName(),
                                OAuth2AuthorizationResponseType.class.getName(),
                                AuthorizationGrantType.class.getName(),
                                ClientAuthenticationMethod.class.getName(),
                                SignatureAlgorithm.class.getName(),
                                OAuth2TokenFormat.class.getName(),
                                OAuth2TokenType.class.getName());
                        boolean typesRegistered = context
                                .consumeMulti(ReflectiveClassBuildItem.class)
                                .stream()
                                .anyMatch(
                                        item -> item.isConstructors()
                                                && item.isMethods()
                                                && item.getClassNames()
                                                        .containsAll(
                                                                expectedTypes));
                        if (!typesRegistered) {
                            throw new IllegalStateException(
                                    "Missing JDBC Jackson reflection registrations: "
                                            + expectedTypes);
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

package io.quarkiverse.authorization.server.deployment;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationResponseType;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.jackson2.SecurityIdentityAttributesConverter;
import io.quarkiverse.authorization.server.runtime.jackson2.SecurityIdentityJacksonBuilder;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

/** Registers schema resources and reflection metadata for the isolated JDBC serialization layer. */
@BuildSteps(onlyIf = AuthorizationServerProcessor.IsEnabled.class)
class JdbcNativeImageProcessor {

    @BuildStep
    NativeImageResourceBuildItem registerJdbcSchemaResources() {
        return new NativeImageResourceBuildItem(
                JdbcRegisteredClientRepository.SCHEMA_LOCATION,
                JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION,
                JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
    }

    @BuildStep
    ReflectiveClassBuildItem registerJdbcJacksonTypesForReflection() {
        return ReflectiveClassBuildItem.builder(
                QuarkusSecurityIdentity.class,
                QuarkusPrincipal.class,
                Principal.class,
                SecurityIdentityJacksonBuilder.class,
                SecurityIdentityAttributesConverter.class,
                SessionInformation.class,
                OAuth2AuthorizationRequest.class,
                OAuth2AuthorizationResponseType.class,
                AuthorizationGrantType.class,
                ClientAuthenticationMethod.class,
                SignatureAlgorithm.class,
                MacAlgorithm.class,
                OAuth2TokenFormat.class,
                OAuth2TokenType.class)
                .constructors()
                .methods()
                .build();
    }

    @BuildStep
    ReflectiveClassBuildItem registerJdbcJacksonDeserializers() {
        // These package-private codecs are instantiated reflectively by the JDBC mapper's MixIns.
        return ReflectiveClassBuildItem.builder(
                "io.quarkiverse.authorization.server.runtime.jackson2.UnmodifiableMapDeserializer",
                "io.quarkiverse.authorization.server.runtime.jackson2.UnmodifiableListDeserializer",
                "io.quarkiverse.authorization.server.runtime.jackson2.UnmodifiableSetDeserializer",
                "io.quarkiverse.authorization.server.runtime.jackson2.OAuth2AuthorizationRequestDeserializer")
                .constructors()
                .build();
    }

    @BuildStep
    ReflectiveClassBuildItem registerJdbcJacksonFields() {
        // These MixIns explicitly use fields and disable getters; method registration alone is insufficient.
        return ReflectiveClassBuildItem.builder(OAuth2AuthorizationRequest.class, OAuth2TokenFormat.class)
                .fields()
                .build();
    }

    @BuildStep
    ReflectiveClassBuildItem registerJdbcJacksonMixIns() {
        // The isolated JDBC mapper installs these MixIns programmatically, outside the application mapper.
        // Jackson must inspect their annotated constructors and methods, even though it never instantiates them.
        return ReflectiveClassBuildItem.builder(
                "io.quarkiverse.authorization.server.runtime.jackson2.DurationMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.HashSetMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.JwsAlgorithmMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.OAuth2AuthorizationRequestMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.OAuth2TokenFormatMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.QuarkusPrincipalMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.QuarkusSecurityIdentityMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.SessionInformationMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.StringValueMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.UnmodifiableListMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.UnmodifiableMapMixin",
                "io.quarkiverse.authorization.server.runtime.jackson2.UnmodifiableSetMixin")
                .constructors()
                .methods()
                .build();
    }

    @BuildStep
    ReflectiveClassBuildItem registerJdbcCollectionTypeNames() {
        // Default typing records these JDK implementation names in JDBC JSON. Jackson supplies
        // their adapters, but native Class.forName still needs the allow-listed types registered.
        return ReflectiveClassBuildItem.builder(
                List.of().getClass(),
                List.of("value").getClass(),
                Map.of().getClass(),
                Map.of("key", "value").getClass(),
                Collections.emptyMap().getClass(),
                Collections.unmodifiableMap(Map.of()).getClass(),
                Collections.unmodifiableList(List.of()).getClass(),
                Collections.unmodifiableSet(java.util.Set.of()).getClass())
                .constructors(false)
                .build();
    }
}

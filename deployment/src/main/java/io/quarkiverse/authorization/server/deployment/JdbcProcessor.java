package io.quarkiverse.authorization.server.deployment;

import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.jdbc.JdbcOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.jdbc.JdbcRegisteredClientRepository;
import io.quarkiverse.authorization.server.runtime.jdbc.JdbcJsonCodecProducer;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBuildItem;

/** JDBC codec assembly and schema resources; JSON trees need no domain reflection registrations. */
@BuildSteps(onlyIf = AuthorizationServerProcessor.IsEnabled.class)
class JdbcProcessor {

    @BuildStep
    AdditionalBeanBuildItem registerJsonCodec() {
        return AdditionalBeanBuildItem.builder().addBeanClass(JdbcJsonCodecProducer.class).build();
    }

    @BuildStep
    NativeImageResourceBuildItem registerJdbcSchemaResources() {
        return new NativeImageResourceBuildItem(
                JdbcRegisteredClientRepository.SCHEMA_LOCATION,
                JdbcOAuth2AuthorizationConsentService.SCHEMA_LOCATION,
                JdbcOAuth2AuthorizationService.SCHEMA_LOCATION);
    }
}

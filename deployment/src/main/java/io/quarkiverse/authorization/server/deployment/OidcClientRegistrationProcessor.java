package io.quarkiverse.authorization.server.deployment;

import java.util.function.BooleanSupplier;

import io.quarkiverse.authorization.server.oidc.registration.OidcClientRegistrationValidator;
import io.quarkiverse.authorization.server.runtime.AuthorizationServerRecorder;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import io.quarkiverse.authorization.server.runtime.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.registration.DefaultRegisteredClientMapper;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientConfigurationService;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientRegistrationService;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcClientRegistrationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcClientRegistrationEndpointSecurityConfiguration;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.runtime.util.StringUtil;
import io.quarkus.vertx.http.deployment.BodyHandlerBuildItem;
import io.quarkus.vertx.http.deployment.spi.RouteBuildItem;
import io.quarkus.vertx.http.runtime.RouteConstants;

/** Installs the optional OIDC client registration endpoint and its CDI components. */
@BuildSteps(onlyIf = {
        AuthorizationServerProcessor.IsEnabled.class,
        OidcProcessor.IsEnabled.class,
        OidcClientRegistrationProcessor.IsEnabled.class
})
class OidcClientRegistrationProcessor {

    @BuildStep
    RuntimeInitializedClassBuildItem initializeRegistrationRandomnessAtRuntime() {
        // Dynamically registered client secrets must use runtime entropy in a native executable.
        return new RuntimeInitializedClassBuildItem(OidcClientRegistrationRegisteredClientConverter.class.getName());
    }

    @BuildStep
    AdditionalBeanBuildItem registerBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        OidcClientRegistrationEndpointHandler.class,
                        OidcClientRegistrationService.class,
                        OidcClientRegistrationValidator.class,
                        DefaultRegisteredClientMapper.class,
                        RegisteredClientOidcClientRegistrationConverter.class,
                        OidcClientConfigurationService.class,
                        OidcClientRegistrationHttpMessageConverter.class,
                        OidcClientRegistrationEndpointSecurityConfiguration.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    void registerEndpoints(
            BuildProducer<RouteBuildItem> routes,
            BodyHandlerBuildItem bodyHandler,
            AuthorizationServerBuildTimeConfig config,
            AuthorizationServerRecorder recorder,
            BeanContainerBuildItem beans) {
        String path = config.oidcClientRegistrationEndpoint();
        // JSON is parsed only for registration POST requests; no global body handler requirement.
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, path))
                        .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(bodyHandler.getHandler())
                        .build());
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, StringUtil.changePrefix(path, "/", "")))
                        .withRouteCustomizer(
                                recorder.clientRegistrationEndpointRoute(beans.getValue()))
                        .withRequestHandler(
                                recorder.clientRegistrationEndpointHandler(beans.getValue()))
                        .build());
    }

    public static class IsEnabled implements BooleanSupplier {
        AuthorizationServerOidcConfig config;

        @Override
        public boolean getAsBoolean() {
            return this.config.clientRegistrationEnabled();
        }
    }
}

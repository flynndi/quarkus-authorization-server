package io.quarkiverse.authorization.server.deployment;

import java.util.function.BooleanSupplier;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.oidc.logout.OidcLogoutValidator;
import io.quarkiverse.authorization.server.runtime.AuthorizationServerRecorder;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.oidc.NoopOidcProviderMetadataCustomizer;
import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcProviderConfigurationHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcUserInfoHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.logout.OidcLogoutService;
import io.quarkiverse.authorization.server.runtime.oidc.session.FormAuthenticationSessionManager;
import io.quarkiverse.authorization.server.runtime.oidc.session.FormAuthenticationSessionObserver;
import io.quarkiverse.authorization.server.runtime.oidc.userinfo.DefaultOidcUserInfoMapper;
import io.quarkiverse.authorization.server.runtime.oidc.userinfo.OidcUserInfoService;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcLogoutEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcLogoutEndpointSecurityConfiguration;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcProviderConfigurationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoAuthenticationMechanism;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoEndpointRequestMatcher;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoEndpointSecurityConfiguration;
import io.quarkiverse.authorization.server.runtime.security.OAuth2AccessTokenIdentityProvider;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.runtime.util.StringUtil;
import io.quarkus.vertx.http.deployment.BodyHandlerBuildItem;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;
import io.quarkus.vertx.http.deployment.spi.RouteBuildItem;
import io.quarkus.vertx.http.runtime.RouteConstants;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;

/** Installs optional OIDC routes, security integration and CDI components during Quarkus augmentation. */
@BuildSteps(onlyIf = { AuthorizationServerProcessor.IsEnabled.class, OidcProcessor.IsEnabled.class })
class OidcProcessor {

    @BuildStep
    AdditionalBeanBuildItem registerRuntimeBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        OidcProviderConfigurationEndpointHandler.class,
                        OidcLogoutEndpointHandler.class,
                        OidcLogoutService.class,
                        DefaultOidcUserInfoMapper.class,
                        OidcLogoutValidator.class,
                        OidcLogoutEndpointSecurityConfiguration.class,
                        OidcProviderConfigurationHttpMessageConverter.class,
                        NoopOidcProviderMetadataCustomizer.class,
                        OidcUserInfoEndpointHandler.class,
                        OidcUserInfoHttpMessageConverter.class,
                        OidcUserInfoService.class,
                        OidcUserInfoAuthenticationMechanism.class,
                        OidcUserInfoEndpointSecurityConfiguration.class,
                        OAuth2AccessTokenIdentityProvider.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    RouteBuildItem registerProviderConfiguration(
            AuthorizationServerBuildTimeConfig config, AuthorizationServerRecorder recorder,
            BeanContainerBuildItem beanContainer) {
        return RouteBuildItem
                .newApplicationRoute(IssuerRoutes.path(config,
                        OidcProviderConfigurationEndpointHandler.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_PATH))
                .withRouteCustomizer(recorder.getEndpointRoute())
                .withRequestHandler(
                        recorder.oidcProviderConfigurationEndpointHandler(beanContainer.getValue()))
                .build();
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    SyntheticBeanBuildItem userInfoRequestMatcher(
            HttpRootPathBuildItem httpRootPath,
            AuthorizationServerBuildTimeConfig config,
            AuthorizationServerRecorder recorder) {
        return SyntheticBeanBuildItem.configure(OidcUserInfoEndpointRequestMatcher.class)
                .scope(Singleton.class)
                .unremovable()
                .supplier(
                        recorder.userInfoRequestMatcher(
                                httpRootPath.relativePath(config.oidcUserInfoEndpoint())))
                .done();
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    RouteBuildItem registerUserInfo(
            AuthorizationServerBuildTimeConfig config,
            AuthorizationServerRecorder recorder,
            BeanContainerBuildItem beanContainer) {
        return RouteBuildItem
                .newApplicationRoute(IssuerRoutes.path(config, StringUtil.changePrefix(config.oidcUserInfoEndpoint(), "/", "")))
                .withRouteCustomizer(recorder.userInfoEndpointRoute(beanContainer.getValue()))
                .withRequestHandler(recorder.userInfoEndpointHandler(beanContainer.getValue()))
                .build();
    }

    public static class IsEnabled implements BooleanSupplier {
        AuthorizationServerOidcConfig config;

        @Override
        public boolean getAsBoolean() {
            return this.config.enabled();
        }
    }

    @BuildStep
    AdditionalBeanBuildItem registerFormSession(VertxHttpBuildTimeConfig httpConfig) {
        if (!httpConfig.auth().form()) {
            return null;
        }
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        FormAuthenticationSessionManager.class,
                        FormAuthenticationSessionObserver.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    void registerLogout(
            BuildProducer<RouteBuildItem> routes,
            BodyHandlerBuildItem bodyHandler,
            AuthorizationServerBuildTimeConfig config,
            AuthorizationServerRecorder recorder,
            BeanContainerBuildItem beanContainer) {
        String path = StringUtil.changePrefix(config.oidcLogoutEndpoint(), "/", "");
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, config.oidcLogoutEndpoint()))
                        .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(bodyHandler.getHandler())
                        .build());
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, path))
                        .withRouteCustomizer(recorder.oidcLogoutEndpointRoute())
                        .withRequestHandler(
                                recorder.oidcLogoutEndpointHandler(beanContainer.getValue()))
                        .build());
    }
}

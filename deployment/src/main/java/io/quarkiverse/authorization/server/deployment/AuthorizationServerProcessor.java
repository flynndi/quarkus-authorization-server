package io.quarkiverse.authorization.server.deployment;

import java.util.List;
import java.util.function.BooleanSupplier;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.runtime.AuthorizationServerRecorder;
import io.quarkiverse.authorization.server.runtime.client.BcryptClientSecretVerifier;
import io.quarkiverse.authorization.server.runtime.client.authentication.ClientJwkSetCache;
import io.quarkiverse.authorization.server.runtime.client.authentication.ClientJwkSetUrlPolicy;
import io.quarkiverse.authorization.server.runtime.client.authentication.ClientSecretAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionVerifier;
import io.quarkiverse.authorization.server.runtime.client.authentication.PublicClientAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.client.authentication.X509ClientCertificateAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.client.authentication.X509ClientCertificateVerifier;
import io.quarkiverse.authorization.server.runtime.client.web.ClientSecretBasicAuthenticationConverter;
import io.quarkiverse.authorization.server.runtime.client.web.ClientSecretPostAuthenticationConverter;
import io.quarkiverse.authorization.server.runtime.client.web.JwtClientAssertionAuthenticationConverter;
import io.quarkiverse.authorization.server.runtime.client.web.OAuth2ClientAuthenticationMechanism;
import io.quarkiverse.authorization.server.runtime.client.web.OAuth2ClientAuthenticationRequestMatcher;
import io.quarkiverse.authorization.server.runtime.client.web.PublicClientAuthenticationConverter;
import io.quarkiverse.authorization.server.runtime.client.web.X509ClientCertificateAuthenticationConverter;
import io.quarkiverse.authorization.server.runtime.config.OAuth2TokenGeneratorProducer;
import io.quarkiverse.authorization.server.runtime.config.RegisteredClientRepositoryProducer;
import io.quarkiverse.authorization.server.runtime.context.CurrentAuthorizationServerContext;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationConsentProcessor;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestProcessor;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.DefaultAuthorizationCodeGenerator;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.DefaultAuthorizationConsentPolicy;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.NoopAuthorizationConsentCustomizer;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.NoopAuthorizationRequestValidator;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.exchange.AuthorizationCodeExchange;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.AuthorizationCodeGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.DefaultConsentPage;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.OAuth2AuthorizationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.OAuth2AuthorizationEndpointSecurityConfiguration;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.PushedAuthorizationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.ClientCredentialsGrant;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.NoopClientCredentialsRequestValidator;
import io.quarkiverse.authorization.server.runtime.grant.clientcredentials.web.ClientCredentialsGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DefaultDeviceConsentPolicy;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceAuthorizationService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceConsentService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.DeviceVerificationService;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.NoopDeviceConsentCustomizer;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.OAuth2DeviceCodeGenerator;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.authorization.OAuth2UserCodeGenerator;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.exchange.DeviceCodeExchange;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.DefaultDeviceVerificationPage;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.DeviceCodeGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceAuthorizationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceVerificationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceVerificationEndpointSecurityConfiguration;
import io.quarkiverse.authorization.server.runtime.grant.password.PasswordGrant;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.password.web.PasswordIdentityAuthenticator;
import io.quarkiverse.authorization.server.runtime.grant.refreshtoken.RefreshTokenGrant;
import io.quarkiverse.authorization.server.runtime.grant.refreshtoken.web.RefreshTokenGrantHandler;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.TokenExchangeGrant;
import io.quarkiverse.authorization.server.runtime.grant.tokenexchange.web.TokenExchangeGrantHandler;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2AuthorizationServerMetadataHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2DeviceAuthorizationResponseHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2JwkSetHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.introspection.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.introspection.web.OAuth2TokenIntrospectionEndpointHandler;
import io.quarkiverse.authorization.server.runtime.introspection.web.OAuth2TokenIntrospectionHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.metadata.NoopAuthorizationServerMetadataCustomizer;
import io.quarkiverse.authorization.server.runtime.revocation.authentication.OAuth2TokenRevocationAuthenticationProvider;
import io.quarkiverse.authorization.server.runtime.revocation.web.OAuth2TokenRevocationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints;
import io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerTenantRegistry;
import io.quarkiverse.authorization.server.runtime.tenant.TenantComponentProducer;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.runtime.token.ConfiguredAuthorizationServerKeySource;
import io.quarkiverse.authorization.server.runtime.token.NoopJwtCustomizer;
import io.quarkiverse.authorization.server.runtime.web.JwkSetEndpointHandler;
import io.quarkiverse.authorization.server.runtime.web.OAuth2AuthorizationServerMetadataEndpointHandler;
import io.quarkiverse.authorization.server.runtime.web.OAuth2TokenEndpointHandler;
import io.quarkiverse.authorization.server.runtime.web.OAuth2TokenEndpointSecurityConfiguration;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkiverse.authorization.server.runtime.web.TokenResponseWriter;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.runtime.util.StringUtil;
import io.quarkus.vertx.http.deployment.BodyHandlerBuildItem;
import io.quarkus.vertx.http.deployment.FilterBuildItem;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;
import io.quarkus.vertx.http.deployment.spi.RouteBuildItem;
import io.quarkus.vertx.http.runtime.RouteConstants;
import io.quarkus.vertx.http.runtime.security.SecurityHandlerPriorities;

@BuildSteps(onlyIf = AuthorizationServerProcessor.IsEnabled.class)
class AuthorizationServerProcessor {

    private static final String FEATURE = "authorization-server";

    @BuildStep
    AdditionalBeanBuildItem tenantComponents(AuthorizationServerBuildTimeConfig config) {
        var beans = AdditionalBeanBuildItem.builder();
        if (config.multipleIssuersAllowed())
            beans.addBeanClasses(
                    AuthorizationServerTenantRegistry.class,
                    TenantComponentProducer.class);
        return beans.setUnremovable().build();
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    FilterBuildItem selectIssuer(AuthorizationServerRecorder recorder, BeanContainerBuildItem beans) {
        return new FilterBuildItem(recorder.issuerSelection(beans.getValue()),
                SecurityHandlerPriorities.AUTHENTICATION + 1);
    }

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    AdditionalBeanBuildItem registerRuntimeBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        CurrentAuthorizationServerContext.class,
                        AuthorizationServerEndpoints.class,
                        BcryptClientSecretVerifier.class,
                        RegisteredClientRepositoryProducer.class,
                        NoopAuthorizationServerMetadataCustomizer.class,
                        OAuth2TokenGeneratorProducer.class,
                        InMemoryOAuth2AuthorizationService.class,
                        InMemoryOAuth2AuthorizationConsentService.class,
                        AuthorizationServerKeyManager.class,
                        ConfiguredAuthorizationServerKeySource.class,
                        NoopJwtCustomizer.class,
                        OAuth2ErrorHttpMessageConverter.class,
                        OAuth2AccessTokenResponseHttpMessageConverter.class,
                        OAuth2AuthorizationServerMetadataHttpMessageConverter.class,
                        OAuth2JwkSetHttpMessageConverter.class,
                        OAuth2TokenIntrospectionHttpMessageConverter.class,
                        ClientSecretBasicAuthenticationConverter.class,
                        ClientSecretPostAuthenticationConverter.class,
                        JwtClientAssertionAuthenticationConverter.class,
                        JwtClientAssertionAuthenticationProvider.class,
                        JwtClientAssertionVerifier.class,
                        ClientJwkSetCache.class,
                        ClientJwkSetUrlPolicy.class,
                        X509ClientCertificateAuthenticationProvider.class,
                        X509ClientCertificateVerifier.class,
                        X509ClientCertificateAuthenticationConverter.class,
                        PublicClientAuthenticationConverter.class,
                        ClientSecretAuthenticationProvider.class,
                        PublicClientAuthenticationProvider.class,
                        OAuth2ClientAuthenticationMechanism.class,
                        OAuth2TokenEndpointHandler.class,
                        OAuth2TokenIntrospectionAuthenticationProvider.class,
                        OAuth2TokenIntrospectionEndpointHandler.class,
                        OAuth2TokenRevocationAuthenticationProvider.class,
                        OAuth2TokenRevocationEndpointHandler.class,
                        TokenResponseWriter.class,
                        ProtocolExecutor.class,
                        JwkSetEndpointHandler.class,
                        OAuth2AuthorizationServerMetadataEndpointHandler.class,
                        OAuth2TokenEndpointSecurityConfiguration.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    AdditionalBeanBuildItem registerDPoPFoundation() {
        // Removable until a protocol service or an application consumes the DPoP foundation.
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        io.quarkiverse.authorization.server.runtime.dpop.DPoPProofVerifier.class,
                        io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding.class,
                        io.quarkiverse.authorization.server.runtime.dpop.InMemoryDPoPReplayStore.class)
                .build();
    }

    @BuildStep
    void initializeProtocolRandomnessAtRuntime(BuildProducer<RuntimeInitializedClassBuildItem> runtimeInitialization) {
        // Defer the owning classes' static initializers so each process creates its SecureRandom instances at runtime.
        // Otherwise their static fields make build-time random state reachable from the native image heap.
        for (Class<?> type : List.of(AuthorizationRequestProcessor.class, DefaultAuthorizationCodeGenerator.class,
                DeviceVerificationService.class, OAuth2DeviceCodeGenerator.class, OAuth2UserCodeGenerator.class)) {
            runtimeInitialization.produce(new RuntimeInitializedClassBuildItem(type.getName()));
        }
    }

    @BuildStep
    AdditionalBeanBuildItem registerPasswordGrantBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        PasswordGrant.class,
                        PasswordIdentityAuthenticator.class,
                        PasswordGrantHandler.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    AdditionalBeanBuildItem registerAuthorizationCodeGrantBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        AuthorizationRequestProcessor.class,
                        NoopAuthorizationRequestValidator.class,
                        NoopAuthorizationConsentCustomizer.class,
                        DefaultAuthorizationConsentPolicy.class,
                        DefaultAuthorizationCodeGenerator.class,
                        AuthorizationConsentProcessor.class,
                        OAuth2AuthorizationEndpointHandler.class,
                        OAuth2AuthorizationEndpointSecurityConfiguration.class,
                        DefaultConsentPage.class,
                        AuthorizationCodeExchange.class,
                        AuthorizationCodeGrantHandler.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    AdditionalBeanBuildItem registerRefreshTokenGrantBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(RefreshTokenGrant.class, RefreshTokenGrantHandler.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    AdditionalBeanBuildItem registerClientCredentialsGrantBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        ClientCredentialsGrant.class,
                        NoopClientCredentialsRequestValidator.class,
                        ClientCredentialsGrantHandler.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    AdditionalBeanBuildItem registerDeviceCodeGrantBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(
                        DeviceAuthorizationService.class,
                        DefaultDeviceConsentPolicy.class,
                        NoopDeviceConsentCustomizer.class,
                        OAuth2DeviceCodeGenerator.class,
                        OAuth2UserCodeGenerator.class,
                        DeviceVerificationService.class,
                        DeviceConsentService.class,
                        OAuth2DeviceAuthorizationEndpointHandler.class,
                        OAuth2DeviceVerificationEndpointHandler.class,
                        OAuth2DeviceVerificationEndpointSecurityConfiguration.class,
                        DefaultDeviceVerificationPage.class,
                        OAuth2DeviceAuthorizationResponseHttpMessageConverter.class,
                        DeviceCodeExchange.class,
                        DeviceCodeGrantHandler.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    AdditionalBeanBuildItem registerTokenExchangeGrantBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(TokenExchangeGrant.class, TokenExchangeGrantHandler.class)
                .setUnremovable()
                .build();
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    SyntheticBeanBuildItem clientAuthenticationRequestMatcher(
            HttpRootPathBuildItem httpRootPath,
            AuthorizationServerBuildTimeConfig config,
            AuthorizationServerRecorder recorder) {
        return SyntheticBeanBuildItem.configure(OAuth2ClientAuthenticationRequestMatcher.class)
                .scope(Singleton.class)
                .unremovable()
                .supplier(
                        recorder.clientAuthenticationRequestMatcher(
                                httpRootPath.relativePath(config.tokenEndpoint()),
                                httpRootPath.relativePath(config.tokenIntrospectionEndpoint()),
                                httpRootPath.relativePath(config.tokenRevocationEndpoint()),
                                httpRootPath.relativePath(config.deviceAuthorizationEndpoint()),
                                config.pushedAuthorizationRequestsEnabled()
                                        ? httpRootPath.relativePath(config.pushedAuthorizationRequestEndpoint())
                                        : null))
                .done();
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    SyntheticBeanBuildItem authorizationServerSettings(
            io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig registrationConfig,
            AuthorizationServerBuildTimeConfig buildTimeConfig,
            AuthorizationServerRecorder recorder) {
        return SyntheticBeanBuildItem.configure(AuthorizationServerSettings.class)
                .scope(Singleton.class)
                .unremovable()
                .setRuntimeInit()
                .supplier(
                        recorder.authorizationServerSettings(
                                buildTimeConfig.multipleIssuersAllowed(),
                                buildTimeConfig.authorizationEndpoint(),
                                buildTimeConfig.deviceAuthorizationEndpoint(),
                                buildTimeConfig.deviceVerificationEndpoint(),
                                buildTimeConfig.tokenEndpoint(),
                                buildTimeConfig.jwkSetEndpoint(),
                                buildTimeConfig.tokenRevocationEndpoint(),
                                buildTimeConfig.tokenIntrospectionEndpoint(),
                                buildTimeConfig.oidcClientRegistrationEndpoint(),
                                buildTimeConfig.oidcUserInfoEndpoint(),
                                buildTimeConfig.oidcLogoutEndpoint(),
                                buildTimeConfig.pushedAuthorizationRequestsEnabled()
                                        ? buildTimeConfig.pushedAuthorizationRequestEndpoint()
                                        : null,
                                registrationConfig.enabled() ? buildTimeConfig.clientRegistrationEndpoint() : null))
                .done();
    }

    @BuildStep
    AdditionalBeanBuildItem registerPushedAuthorizationBean(AuthorizationServerBuildTimeConfig config) {
        var builder = AdditionalBeanBuildItem.builder();
        if (config.pushedAuthorizationRequestsEnabled())
            builder.addBeanClass(PushedAuthorizationEndpointHandler.class);
        return builder.setUnremovable().build();
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    void registerEndpoints(
            HttpRootPathBuildItem httpRootPath, BuildProducer<RouteBuildItem> routes,
            BodyHandlerBuildItem bodyHandler,
            BeanContainerBuildItem beanContainer,
            AuthorizationServerBuildTimeConfig config,
            AuthorizationServerRecorder recorder) {
        if (config.pushedAuthorizationRequestsEnabled()) {
            routes.produce(
                    RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, config.pushedAuthorizationRequestEndpoint()))
                            .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                            .withRouteCustomizer(recorder.formPostEndpointRoute())
                            .withRequestHandler(bodyHandler.getHandler()).build());
            routes.produce(RouteBuildItem
                    .newApplicationRoute(IssuerRoutes.path(config,
                            StringUtil.changePrefix(config.pushedAuthorizationRequestEndpoint(), "/", "")))
                    .withRouteCustomizer(recorder.pushedAuthorizationEndpointRoute(beanContainer.getValue()))
                    .withRequestHandler(recorder.pushedAuthorizationEndpointHandler(beanContainer.getValue())).build());
        }
        // Parse only Authorization Server form endpoints; client authentication runs before
        // protected handlers.
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, config.authorizationEndpoint()))
                        .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(bodyHandler.getHandler())
                        .build());
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, config.tokenEndpoint()))
                        .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(bodyHandler.getHandler())
                        .build());
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, config.deviceAuthorizationEndpoint()))
                        .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(bodyHandler.getHandler())
                        .build());
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, config.deviceVerificationEndpoint()))
                        .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(bodyHandler.getHandler())
                        .build());
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, config.tokenIntrospectionEndpoint()))
                        .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(bodyHandler.getHandler())
                        .build());
        routes.produce(
                RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, config.tokenRevocationEndpoint()))
                        .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(bodyHandler.getHandler())
                        .build());

        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(
                                IssuerRoutes.path(config, StringUtil.changePrefix(config.authorizationEndpoint(), "/", "")))
                        .withRouteCustomizer(recorder.getEndpointRoute())
                        .withRequestHandler(
                                recorder.authorizationEndpointHandler(beanContainer.getValue()))
                        .build());
        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(
                                IssuerRoutes.path(config, StringUtil.changePrefix(config.authorizationEndpoint(), "/", "")))
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(
                                recorder.authorizationEndpointHandler(beanContainer.getValue()))
                        .build());

        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(
                                IssuerRoutes.path(config, StringUtil.changePrefix(config.tokenEndpoint(), "/", "")))
                        .withRouteCustomizer(
                                recorder.clientAuthenticationEndpointRoute(
                                        beanContainer.getValue()))
                        .withRequestHandler(recorder.tokenEndpointHandler(beanContainer.getValue()))
                        .build());
        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(IssuerRoutes.path(config,
                                StringUtil.changePrefix(config.deviceAuthorizationEndpoint(), "/", "")))
                        .withRouteCustomizer(
                                recorder.clientAuthenticationEndpointRoute(
                                        beanContainer.getValue()))
                        .withRequestHandler(
                                recorder.deviceAuthorizationEndpointHandler(
                                        beanContainer.getValue()))
                        .build());
        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(IssuerRoutes.path(config,
                                StringUtil.changePrefix(config.deviceVerificationEndpoint(), "/", "")))
                        .withRouteCustomizer(recorder.getEndpointRoute())
                        .withRequestHandler(
                                recorder.deviceVerificationEndpointHandler(
                                        beanContainer.getValue()))
                        .build());
        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(IssuerRoutes.path(config,
                                StringUtil.changePrefix(config.deviceVerificationEndpoint(), "/", "")))
                        .withRouteCustomizer(recorder.formPostEndpointRoute())
                        .withRequestHandler(
                                recorder.deviceVerificationEndpointHandler(
                                        beanContainer.getValue()))
                        .build());
        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(IssuerRoutes.path(config,
                                StringUtil.changePrefix(config.tokenIntrospectionEndpoint(), "/", "")))
                        .withRouteCustomizer(
                                recorder.clientAuthenticationEndpointRoute(
                                        beanContainer.getValue()))
                        .withRequestHandler(
                                recorder.tokenIntrospectionEndpointHandler(
                                        beanContainer.getValue()))
                        .build());
        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(
                                IssuerRoutes.path(config, StringUtil.changePrefix(config.tokenRevocationEndpoint(), "/", "")))
                        .withRouteCustomizer(
                                recorder.clientAuthenticationEndpointRoute(
                                        beanContainer.getValue()))
                        .withRequestHandler(
                                recorder.tokenRevocationEndpointHandler(beanContainer.getValue()))
                        .build());

        routes.produce(
                RouteBuildItem
                        .newApplicationRoute(
                                IssuerRoutes.path(config, StringUtil.changePrefix(config.jwkSetEndpoint(), "/", "")))
                        .withRouteCustomizer(recorder.getEndpointRoute())
                        .withRequestHandler(
                                recorder.jwkSetEndpointHandler(beanContainer.getValue()))
                        .build());
        routes.produce(
                (config.multipleIssuersAllowed()
                        ? RouteBuildItem.newAbsoluteRoute(
                                "/" + OAuth2AuthorizationServerMetadataEndpointHandler.DEFAULT_METADATA_ENDPOINT_PATH
                                        + httpRootPath.relativePath("./:issuer"))
                        : RouteBuildItem.newApplicationRoute(
                                OAuth2AuthorizationServerMetadataEndpointHandler.DEFAULT_METADATA_ENDPOINT_PATH))
                        .withRouteCustomizer(
                                config.multipleIssuersAllowed() ? recorder.issuerMetadataRoute(beanContainer.getValue())
                                        : recorder.getEndpointRoute())
                        .withRequestHandler(
                                recorder.metadataEndpointHandler(beanContainer.getValue()))
                        .build());
    }

    public static class IsEnabled implements BooleanSupplier {

        AuthorizationServerBuildTimeConfig config;

        @Override
        public boolean getAsBoolean() {
            return this.config.enabled();
        }
    }
}

package io.quarkiverse.authorization.server.deployment;

import java.util.function.BooleanSupplier;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.runtime.AuthorizationServerRecorder;
import io.quarkiverse.authorization.server.runtime.client.authentication.BcryptClientSecretEncoder;
import io.quarkiverse.authorization.server.runtime.client.registration.DefaultClientRegistrationScopeValidator;
import io.quarkiverse.authorization.server.runtime.client.registration.DefaultOAuth2ClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.runtime.client.registration.NoopRegistrationClientSettingsCustomizer;
import io.quarkiverse.authorization.server.runtime.client.registration.NoopRegistrationTokenSettingsCustomizer;
import io.quarkiverse.authorization.server.runtime.client.registration.OAuth2ClientRegistrationService;
import io.quarkiverse.authorization.server.runtime.client.registration.web.ClientRegistrationAuthenticationMechanism;
import io.quarkiverse.authorization.server.runtime.client.registration.web.ClientRegistrationEndpointRequestMatcher;
import io.quarkiverse.authorization.server.runtime.client.registration.web.OAuth2ClientRegistrationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.client.registration.web.OAuth2ClientRegistrationEndpointSecurityConfiguration;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.security.OAuth2AccessTokenIdentityProvider;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanContainerBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.annotations.*;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.runtime.util.StringUtil;
import io.quarkus.vertx.http.deployment.BodyHandlerBuildItem;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;
import io.quarkus.vertx.http.deployment.spi.RouteBuildItem;
import io.quarkus.vertx.http.runtime.RouteConstants;

/** Shared registration security and optional RFC 7591 endpoint assembly. */
@BuildSteps(onlyIf = AuthorizationServerProcessor.IsEnabled.class)
class ClientRegistrationProcessor {
    @BuildStep(onlyIf = AnyRegistrationEnabled.class)
    AdditionalBeanBuildItem commonBeans() {
        return AdditionalBeanBuildItem.builder().addBeanClasses(ClientRegistrationAuthenticationMechanism.class,
                OAuth2AccessTokenIdentityProvider.class, BcryptClientSecretEncoder.class,
                NoopRegistrationClientSettingsCustomizer.class, NoopRegistrationTokenSettingsCustomizer.class,
                DefaultClientRegistrationScopeValidator.class)
                .setUnremovable().build();
    }

    @BuildStep(onlyIf = AnyRegistrationEnabled.class)
    @Record(ExecutionTime.STATIC_INIT)
    SyntheticBeanBuildItem requestMatcher(HttpRootPathBuildItem rootPath, AuthorizationServerBuildTimeConfig paths,
            AuthorizationServerClientRegistrationConfig oauth, AuthorizationServerOidcConfig oidc,
            AuthorizationServerRecorder recorder) {
        String oauthPath = oauth.enabled() ? rootPath.relativePath(paths.clientRegistrationEndpoint()) : null;
        String oidcPath = oidc.enabled() && oidc.clientRegistrationEnabled()
                ? rootPath.relativePath(paths.oidcClientRegistrationEndpoint())
                : null;
        return SyntheticBeanBuildItem.configure(ClientRegistrationEndpointRequestMatcher.class).scope(Singleton.class)
                .unremovable().supplier(recorder.clientRegistrationRequestMatcher(oauthPath, oidcPath)).done();
    }

    @BuildStep(onlyIf = OAuthRegistrationEnabled.class)
    AdditionalBeanBuildItem oauthBeans() {
        return AdditionalBeanBuildItem.builder().addBeanClasses(OAuth2ClientRegistrationEndpointHandler.class,
                OAuth2ClientRegistrationEndpointSecurityConfiguration.class, OAuth2ClientRegistrationService.class,
                DefaultOAuth2ClientRegistrationRequestValidator.class).setUnremovable().build();
    }

    @BuildStep(onlyIf = OAuthRegistrationEnabled.class)
    @Record(ExecutionTime.RUNTIME_INIT)
    void routes(BuildProducer<RouteBuildItem> routes, BodyHandlerBuildItem bodyHandler,
            AuthorizationServerBuildTimeConfig config, AuthorizationServerRecorder recorder, BeanContainerBuildItem beans) {
        String path = config.clientRegistrationEndpoint();
        routes.produce(RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, path))
                .withOrder(RouteConstants.ROUTE_ORDER_BODY_HANDLER)
                .withRouteCustomizer(recorder.formPostEndpointRoute()).withRequestHandler(bodyHandler.getHandler()).build());
        routes.produce(RouteBuildItem.newApplicationRoute(IssuerRoutes.path(config, StringUtil.changePrefix(path, "/", "")))
                .withRouteCustomizer(recorder.oauthClientRegistrationEndpointRoute(beans.getValue()))
                .withRequestHandler(recorder.oauthClientRegistrationEndpointHandler(beans.getValue())).build());
    }

    public static class OAuthRegistrationEnabled implements BooleanSupplier {
        AuthorizationServerClientRegistrationConfig config;

        public boolean getAsBoolean() {
            return this.config.enabled();
        }
    }

    public static class AnyRegistrationEnabled implements BooleanSupplier {
        AuthorizationServerClientRegistrationConfig oauth;
        AuthorizationServerOidcConfig oidc;

        public boolean getAsBoolean() {
            return this.oauth.enabled() || this.oidc.enabled() && this.oidc.clientRegistrationEnabled();
        }
    }
}

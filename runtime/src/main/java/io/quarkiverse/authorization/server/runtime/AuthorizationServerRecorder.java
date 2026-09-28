package io.quarkiverse.authorization.server.runtime;

import java.net.URI;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import io.quarkiverse.authorization.server.runtime.client.registration.web.ClientRegistrationAuthenticationMechanism;
import io.quarkiverse.authorization.server.runtime.client.registration.web.ClientRegistrationEndpointRequestMatcher;
import io.quarkiverse.authorization.server.runtime.client.web.OAuth2ClientAuthenticationMechanism;
import io.quarkiverse.authorization.server.runtime.client.web.OAuth2ClientAuthenticationRequestMatcher;
import io.quarkiverse.authorization.server.runtime.client.web.OAuth2ClientAuthenticationRequestMatcher.Endpoint;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.DefaultLoginPage;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.OAuth2AuthorizationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web.PushedAuthorizationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceAuthorizationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.grant.devicecode.web.OAuth2DeviceVerificationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.introspection.web.OAuth2TokenIntrospectionEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcClientRegistrationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcLogoutEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcProviderConfigurationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoAuthenticationMechanism;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoEndpointHandler;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcUserInfoEndpointRequestMatcher;
import io.quarkiverse.authorization.server.runtime.revocation.web.OAuth2TokenRevocationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints;
import io.quarkiverse.authorization.server.runtime.web.JwkSetEndpointHandler;
import io.quarkiverse.authorization.server.runtime.web.OAuth2AuthorizationServerMetadataEndpointHandler;
import io.quarkiverse.authorization.server.runtime.web.OAuth2TokenEndpointHandler;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.runtime.LaunchMode;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.RoutingContext;

@Recorder
public class AuthorizationServerRecorder {

    private final RuntimeValue<AuthorizationServerRuntimeConfig> runtimeConfig;

    public AuthorizationServerRecorder(RuntimeValue<AuthorizationServerRuntimeConfig> runtimeConfig) {
        this.runtimeConfig = runtimeConfig;
    }

    public Handler<RoutingContext> issuerSelection(BeanContainer beans) {
        var endpoints = beans.beanInstance(AuthorizationServerEndpoints.class);
        return endpoints::select;
    }

    public Consumer<Route> issuerMetadataRoute(BeanContainer beans) {
        var endpoints = beans.beanInstance(AuthorizationServerEndpoints.class);
        // Absolute discovery routes can live outside the application root and its HTTP filters.
        return route -> route.method(HttpMethod.GET).handler(endpoints::select);
    }

    public Handler<RoutingContext> defaultLoginPage(BeanContainer beans) {
        return beans.beanInstance(DefaultLoginPage.class);
    }

    public Supplier<AuthorizationServerSettings> authorizationServerSettings(
            boolean multipleIssuersAllowed, String authorizationEndpoint,
            String deviceAuthorizationEndpoint,
            String deviceVerificationEndpoint,
            String tokenEndpoint,
            String jwkSetEndpoint,
            String tokenRevocationEndpoint,
            String tokenIntrospectionEndpoint,
            String oidcClientRegistrationEndpoint,
            String oidcUserInfoEndpoint,
            String oidcLogoutEndpoint,
            String pushedAuthorizationRequestEndpoint, String clientRegistrationEndpoint) {
        return () -> {
            AuthorizationServerSettings.Builder builder = AuthorizationServerSettings.builder()
                    .multipleIssuersAllowed(multipleIssuersAllowed)
                    .authorizationEndpoint(authorizationEndpoint)
                    .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint)
                    .deviceVerificationEndpoint(deviceVerificationEndpoint)
                    .tokenEndpoint(tokenEndpoint)
                    .jwkSetEndpoint(jwkSetEndpoint)
                    .tokenRevocationEndpoint(tokenRevocationEndpoint)
                    .tokenIntrospectionEndpoint(tokenIntrospectionEndpoint)
                    .oidcClientRegistrationEndpoint(oidcClientRegistrationEndpoint)
                    .oidcUserInfoEndpoint(oidcUserInfoEndpoint)
                    .oidcLogoutEndpoint(oidcLogoutEndpoint);
            if (pushedAuthorizationRequestEndpoint != null) {
                builder.pushedAuthorizationRequestEndpoint(pushedAuthorizationRequestEndpoint);
            }
            if (clientRegistrationEndpoint != null)
                builder.clientRegistrationEndpoint(clientRegistrationEndpoint);
            String issuer = multipleIssuersAllowed ? null : AuthorizationServerRecorder.issuer(this.runtimeConfig.getValue());
            if (issuer != null) {
                builder.issuer(issuer);
            }
            return builder.build();
        };
    }

    public Supplier<OAuth2ClientAuthenticationRequestMatcher> clientAuthenticationRequestMatcher(
            String tokenEndpointPath, String tokenIntrospectionEndpointPath,
            String tokenRevocationEndpointPath, String deviceAuthorizationEndpointPath,
            String pushedAuthorizationRequestEndpointPath) {
        return () -> {
            var endpoints = new java.util.HashSet<>(Set.of(new Endpoint(HttpMethod.POST, tokenEndpointPath),
                    new Endpoint(HttpMethod.POST, tokenIntrospectionEndpointPath),
                    new Endpoint(HttpMethod.POST, tokenRevocationEndpointPath),
                    new Endpoint(HttpMethod.POST, deviceAuthorizationEndpointPath)));
            var publicEndpoints = new java.util.HashSet<>(Set.of(new Endpoint(HttpMethod.POST, tokenEndpointPath),
                    new Endpoint(HttpMethod.POST, deviceAuthorizationEndpointPath)));
            if (pushedAuthorizationRequestEndpointPath != null) {
                var endpoint = new Endpoint(HttpMethod.POST, pushedAuthorizationRequestEndpointPath);
                endpoints.add(endpoint);
                publicEndpoints.add(endpoint);
            }
            return new OAuth2ClientAuthenticationRequestMatcher(endpoints, publicEndpoints);
        };
    }

    public Handler<RoutingContext> pushedAuthorizationEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(PushedAuthorizationEndpointHandler.class);
    }

    public Handler<RoutingContext> tokenEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OAuth2TokenEndpointHandler.class);
    }

    public Handler<RoutingContext> tokenIntrospectionEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OAuth2TokenIntrospectionEndpointHandler.class);
    }

    public Handler<RoutingContext> tokenRevocationEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OAuth2TokenRevocationEndpointHandler.class);
    }

    public Handler<RoutingContext> deviceAuthorizationEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OAuth2DeviceAuthorizationEndpointHandler.class);
    }

    public Handler<RoutingContext> deviceVerificationEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OAuth2DeviceVerificationEndpointHandler.class);
    }

    public Handler<RoutingContext> authorizationEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OAuth2AuthorizationEndpointHandler.class);
    }

    public Handler<RoutingContext> jwkSetEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(JwkSetEndpointHandler.class);
    }

    public Handler<RoutingContext> metadataEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OAuth2AuthorizationServerMetadataEndpointHandler.class);
    }

    public Consumer<Route> formPostEndpointRoute() {
        return route -> route.method(HttpMethod.POST);
    }

    public Handler<RoutingContext> oidcProviderConfigurationEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OidcProviderConfigurationEndpointHandler.class);
    }

    public Supplier<OidcUserInfoEndpointRequestMatcher> userInfoRequestMatcher(String path) {
        return () -> new OidcUserInfoEndpointRequestMatcher(path);
    }

    public Handler<RoutingContext> userInfoEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OidcUserInfoEndpointHandler.class);
    }

    public Consumer<Route> oidcLogoutEndpointRoute() {
        return route -> route.method(HttpMethod.GET).method(HttpMethod.POST);
    }

    public Consumer<Route> userInfoEndpointRoute(BeanContainer beanContainer) {
        var mechanism = beanContainer.beanInstance(OidcUserInfoAuthenticationMechanism.class);
        return route -> route.method(HttpMethod.GET).method(HttpMethod.POST).failureHandler(mechanism::handleFailure);
    }

    public Consumer<Route> clientAuthenticationEndpointRoute(BeanContainer beanContainer) {
        var mechanism = beanContainer.beanInstance(OAuth2ClientAuthenticationMechanism.class);
        return route -> route.method(HttpMethod.POST).failureHandler(mechanism::handleFailure);
    }

    public Consumer<Route> pushedAuthorizationEndpointRoute(BeanContainer beanContainer) {
        var mechanism = beanContainer.beanInstance(OAuth2ClientAuthenticationMechanism.class);
        // The PAR handler returns 405 for methods other than POST.
        return route -> route.failureHandler(mechanism::handleFailure);
    }

    public Handler<RoutingContext> oidcLogoutEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OidcLogoutEndpointHandler.class);
    }

    public Supplier<ClientRegistrationEndpointRequestMatcher> clientRegistrationRequestMatcher(String oauthPath,
            String oidcPath) {
        return () -> new ClientRegistrationEndpointRequestMatcher(oauthPath, oidcPath);
    }

    public Handler<RoutingContext> oauthClientRegistrationEndpointHandler(BeanContainer beans) {
        return beans.beanInstance(
                io.quarkiverse.authorization.server.runtime.client.registration.web.OAuth2ClientRegistrationEndpointHandler.class);
    }

    public Consumer<Route> oauthClientRegistrationEndpointRoute(BeanContainer beans) {
        var mechanism = beans.beanInstance(ClientRegistrationAuthenticationMechanism.class);
        return route -> route.method(HttpMethod.POST).failureHandler(mechanism::handleFailure);
    }

    public Handler<RoutingContext> clientRegistrationEndpointHandler(BeanContainer beanContainer) {
        return beanContainer.beanInstance(OidcClientRegistrationEndpointHandler.class);
    }

    public Consumer<Route> clientRegistrationEndpointRoute(BeanContainer beanContainer) {
        var mechanism = beanContainer.beanInstance(ClientRegistrationAuthenticationMechanism.class);
        return route -> route.method(HttpMethod.GET).method(HttpMethod.POST).failureHandler(mechanism::handleFailure);
    }

    public Consumer<Route> getEndpointRoute() {
        return route -> route.method(HttpMethod.GET);
    }

    private static String issuer(AuthorizationServerRuntimeConfig config) {
        String issuer = config.issuer().orElse(null);
        if (issuer == null || issuer.isBlank()) {
            if (LaunchMode.current() == LaunchMode.NORMAL) {
                throw new IllegalStateException(
                        "quarkus.authorization-server.issuer must be configured");
            }
            return null;
        }
        URI issuerUri;
        try {
            issuerUri = URI.create(issuer);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(
                    "quarkus.authorization-server.issuer must be a valid URL", exception);
        }
        if (!issuerUri.isAbsolute()
                || issuerUri.getHost() == null
                || !("http".equalsIgnoreCase(issuerUri.getScheme()) || "https".equalsIgnoreCase(issuerUri.getScheme()))
                || issuerUri.getRawQuery() != null
                || issuerUri.getRawFragment() != null) {
            throw new IllegalStateException(
                    "quarkus.authorization-server.issuer must be an absolute HTTP(S) URL without"
                            + " query or fragment");
        }
        return issuer;
    }
}

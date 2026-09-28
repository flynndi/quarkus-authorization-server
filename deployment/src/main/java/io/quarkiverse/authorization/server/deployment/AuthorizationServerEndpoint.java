package io.quarkiverse.authorization.server.deployment;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.oidc.web.OidcProviderConfigurationEndpointHandler;
import io.quarkiverse.authorization.server.runtime.web.OAuth2AuthorizationServerMetadataEndpointHandler;
import io.quarkus.runtime.util.StringUtil;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;

/** Effective route inventory shared by conflict diagnostics and the development UI. */
record AuthorizationServerEndpoint(String name, String path, Set<String> methods, String issuerRelativePath) {
    static List<AuthorizationServerEndpoint> configuredEndpoints(AuthorizationServerBuildTimeConfig config,
            AuthorizationServerOidcConfig oidc, AuthorizationServerClientRegistrationConfig registration,
            HttpRootPathBuildItem root) {
        if (!config.enabled()) {
            return List.of();
        }
        List<AuthorizationServerEndpoint> endpoints = new ArrayList<>();
        endpoints.add(
                AuthorizationServerEndpoint.configured(config, root, "authorization-endpoint", config.authorizationEndpoint(),
                        "GET", "POST"));
        endpoints.add(AuthorizationServerEndpoint.configured(config, root, "token-endpoint", config.tokenEndpoint(), "POST"));
        endpoints.add(AuthorizationServerEndpoint.configured(config, root, "jwk-set-endpoint", config.jwkSetEndpoint(), "GET"));
        endpoints.add(
                AuthorizationServerEndpoint.configured(config, root, "token-introspection-endpoint",
                        config.tokenIntrospectionEndpoint(), "POST"));
        endpoints.add(AuthorizationServerEndpoint.configured(config, root, "token-revocation-endpoint",
                config.tokenRevocationEndpoint(), "POST"));
        endpoints.add(AuthorizationServerEndpoint.configured(config, root, "device-authorization-endpoint",
                config.deviceAuthorizationEndpoint(),
                "POST"));
        endpoints.add(AuthorizationServerEndpoint.configured(config, root, "device-verification-endpoint",
                config.deviceVerificationEndpoint(),
                "GET", "POST"));
        if (config.pushedAuthorizationRequestsEnabled()) {
            // PAR claims every method to return its own 405 response; even a GET route would be shadowed.
            endpoints.add(AuthorizationServerEndpoint.configured(config, root, "pushed-authorization-request-endpoint",
                    config.pushedAuthorizationRequestEndpoint(), "*"));
        }
        if (registration.enabled()) {
            endpoints.add(AuthorizationServerEndpoint.configured(config, root, "client-registration-endpoint",
                    config.clientRegistrationEndpoint(),
                    "POST"));
        }
        String metadata = OAuth2AuthorizationServerMetadataEndpointHandler.DEFAULT_METADATA_ENDPOINT_PATH;
        endpoints.add(new AuthorizationServerEndpoint("OAuth authorization server metadata", config.multipleIssuersAllowed()
                ? "/" + metadata + root.relativePath("./:issuer")
                : root.relativePath(metadata), Set.of("GET"), "/" + metadata));
        if (oidc.enabled()) {
            endpoints.add(
                    AuthorizationServerEndpoint.configured(config, root, "oidc-user-info-endpoint",
                            config.oidcUserInfoEndpoint(), "GET", "POST"));
            endpoints
                    .add(AuthorizationServerEndpoint.configured(config, root, "oidc-logout-endpoint",
                            config.oidcLogoutEndpoint(), "GET", "POST"));
            endpoints.add(new AuthorizationServerEndpoint("OIDC provider configuration",
                    root.relativePath(IssuerRoutes.path(config,
                            OidcProviderConfigurationEndpointHandler.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_PATH)),
                    Set.of("GET"),
                    "/" + OidcProviderConfigurationEndpointHandler.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_PATH));
            if (oidc.clientRegistrationEnabled()) {
                endpoints.add(AuthorizationServerEndpoint.configured(config, root, "oidc-client-registration-endpoint",
                        config.oidcClientRegistrationEndpoint(), "GET", "POST"));
            }
        }
        return List.copyOf(endpoints);
    }

    private static AuthorizationServerEndpoint configured(AuthorizationServerBuildTimeConfig config, HttpRootPathBuildItem root,
            String property, String path, String... methods) {
        return new AuthorizationServerEndpoint("quarkus.authorization-server." + property,
                root.relativePath(IssuerRoutes.path(config, StringUtil.changePrefix(path, "/", ""))), Set.of(methods), path);
    }
}

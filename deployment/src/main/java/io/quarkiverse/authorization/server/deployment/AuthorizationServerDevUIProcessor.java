package io.quarkiverse.authorization.server.deployment;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.devui.AuthorizationServerDevUIService;
import io.quarkus.deployment.IsLocalDevelopment;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.devui.spi.JsonRPCProvidersBuildItem;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import io.quarkus.devui.spi.page.Page;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;

/** Contributes build-time routes and a read-only runtime projection to the development UI. */
@BuildSteps(onlyIf = AuthorizationServerProcessor.IsEnabled.class)
class AuthorizationServerDevUIProcessor {
    @BuildStep
    JsonRPCProvidersBuildItem runtimeOverview() {
        // The SPI also validates execution annotations outside dev mode. Quarkus installs the service only in dev mode.
        return new JsonRPCProvidersBuildItem(AuthorizationServerDevUIService.class);
    }

    @BuildStep(onlyIf = IsLocalDevelopment.class)
    CardPageBuildItem overview(AuthorizationServerBuildTimeConfig config, AuthorizationServerOidcConfig oidc,
            AuthorizationServerClientRegistrationConfig registration, HttpRootPathBuildItem root) {
        var endpoints = AuthorizationServerEndpoint.configuredEndpoints(config, oidc, registration, root);
        var card = new CardPageBuildItem();
        card.addPage(Page.webComponentPageBuilder().title("Overview").icon("font-awesome-solid:shield-halved")
                .componentLink("qwc-authorization-server-overview.js").staticLabel(Integer.toString(endpoints.size())));
        card.addBuildTimeData("overview", Map.of(
                "httpRoot", root.getRootPath(),
                "multipleIssuers", config.multipleIssuersAllowed(),
                "features", List.of(
                        Map.of("name", "OpenID Connect", "enabled", oidc.enabled()),
                        Map.of("name", "Pushed Authorization Requests", "enabled", config.pushedAuthorizationRequestsEnabled()),
                        Map.of("name", "OAuth client registration", "enabled", registration.enabled()),
                        Map.of("name", "OIDC client registration", "enabled",
                                oidc.enabled() && oidc.clientRegistrationEnabled()),
                        Map.of("name", "Default login page integration", "enabled", config.defaultLoginPageEnabled())),
                "endpoints", endpoints.stream()
                        .map(endpoint -> AuthorizationServerDevUIProcessor.endpointData(endpoint,
                                config.multipleIssuersAllowed()))
                        .toList()));
        return card;
    }

    private static Map<String, Object> endpointData(AuthorizationServerEndpoint endpoint, boolean multipleIssuers) {
        boolean reservesAllMethods = endpoint.methods().contains("*");
        boolean readable = Set.of("quarkus.authorization-server.jwk-set-endpoint",
                "OAuth authorization server metadata", "OIDC provider configuration").contains(endpoint.name());
        // PAR owns every method for routing, but only POST is a supported protocol operation.
        return Map.of("name", endpoint.name(),
                "path", multipleIssuers ? endpoint.path().replace(":issuer", "{issuer}") : endpoint.path(),
                "issuerPath", endpoint.issuerRelativePath(),
                "methods", new TreeSet<>(reservesAllMethods ? Set.of("POST") : endpoint.methods()),
                "note", reservesAllMethods ? "Other methods return 405" : "",
                "readable", readable);
    }
}

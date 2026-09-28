package io.quarkiverse.authorization.server.deployment;

import io.quarkus.runtime.util.StringUtil;

/** Adds the tenant path parameter when registering application protocol routes at build time. */
final class IssuerRoutes {

    private IssuerRoutes() {
    }

    static String path(AuthorizationServerBuildTimeConfig config, String endpoint) {
        String path = StringUtil.changePrefix(endpoint, "/", "");
        if (!config.multipleIssuersAllowed()) {
            return endpoint;
        }
        // Keep relative routes relative; a leading ':' would otherwise be parsed as URI scheme syntax.
        return (endpoint.startsWith("/") ? "/" : "./") + ":issuer/" + path;
    }
}

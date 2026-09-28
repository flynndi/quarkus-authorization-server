package io.quarkiverse.authorization.server.runtime.tenant;

import java.net.URI;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.context.CurrentAuthorizationServerContext;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.runtime.util.StringUtil;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;
import io.smallrye.common.vertx.ContextLocals;
import io.vertx.ext.web.RoutingContext;

/** Canonical issuer allowlist and protocol path mapping. Host/Forwarded headers never define an issuer. */
@Singleton
public final class AuthorizationServerEndpoints {
    public static final String OAUTH_METADATA = ".well-known/oauth-authorization-server";
    private static final String PROTOCOL_PATH = AuthorizationServerEndpoints.class.getName();
    private final String root;
    private final boolean multiple;
    private final Map<String, AuthorizationServerSettings> tenants;
    private final Set<String> endpoints;

    @Inject
    public AuthorizationServerEndpoints(AuthorizationServerSettings settings, AuthorizationServerRuntimeConfig config,
            AuthorizationServerOidcConfig oidc, VertxHttpBuildTimeConfig http) {
        this.root = http.rootPath().endsWith("/") ? http.rootPath() : http.rootPath() + "/";
        this.multiple = settings.isMultipleIssuersAllowed();
        if (!this.multiple && !config.issuers().isEmpty()) {
            throw new IllegalStateException("issuers requires multiple-issuers-allowed=true");
        }
        if (this.multiple && (config.issuer().isPresent() || config.issuers().isEmpty())) {
            throw new IllegalStateException("Multiple issuers requires a nonempty issuers map and no single issuer setting");
        }
        if (this.multiple && !config.clients().isEmpty()) {
            throw new IllegalStateException(
                    "Multiple issuers uses tenant repositories; global clients configuration is not supported");
        }
        if (this.multiple && (!"RS256".equals(config.signing().algorithm()) || !config.signing().keys().isEmpty()
                || config.signing().activeKeyId().isPresent() || config.signing().keyId().isPresent()
                || config.signing().privateKeyLocation().isPresent() || config.signing().publicKeyLocation().isPresent())) {
            throw new IllegalStateException(
                    "Multiple issuers uses tenant key sources; global signing key configuration is not supported");
        }
        Map<String, AuthorizationServerSettings> tenants = new LinkedHashMap<>();
        config.issuers().forEach((id, issuer) -> {
            if (!id.matches("[A-Za-z0-9_-]+")) {
                throw new IllegalStateException("Issuer tenant identifiers must be single path segments: " + id);
            }
            URI uri = URI.create(issuer);
            if (!Set.of("http", "https").contains(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null
                    || uri.getRawQuery() != null || uri.getRawFragment() != null
                    || !(this.root + id).equals(uri.getRawPath())) {
                throw new IllegalStateException(
                        "Issuer URL must be an absolute HTTP(S) URL ending in the HTTP root path and tenant identifier: " + id);
            }
            tenants.put(id, AuthorizationServerSettings.withSettings(settings.getSettings()).issuer(issuer).build());
        });
        this.tenants = Map.copyOf(tenants);
        // Distinct HTTP methods may share a path; this set only identifies protocol paths for issuer selection.
        Set<String> endpoints = new HashSet<>(List.of(settings.getAuthorizationEndpoint(), settings.getTokenEndpoint(),
                settings.getJwkSetEndpoint(), settings.getTokenIntrospectionEndpoint(), settings.getTokenRevocationEndpoint(),
                settings.getDeviceAuthorizationEndpoint(), settings.getDeviceVerificationEndpoint(), "/" + OAUTH_METADATA));
        if (settings.getPushedAuthorizationRequestEndpoint() != null) {
            endpoints.add(settings.getPushedAuthorizationRequestEndpoint());
        }
        if (settings.getClientRegistrationEndpoint() != null) {
            endpoints.add(settings.getClientRegistrationEndpoint());
        }
        if (oidc.enabled()) {
            endpoints.add("/.well-known/openid-configuration");
            endpoints.add(settings.getOidcUserInfoEndpoint());
            endpoints.add(settings.getOidcLogoutEndpoint());
            if (oidc.clientRegistrationEnabled()) {
                endpoints.add(settings.getOidcClientRegistrationEndpoint());
            }
        }
        this.endpoints = Set.copyOf(endpoints);
    }

    public Map<String, AuthorizationServerSettings> tenants() {
        return this.tenants;
    }

    /** Exact HttpSecurity paths; OAuth discovery is absolute, other paths are relative to the HTTP root. */
    public String[] paths(String endpoint) {
        String path = StringUtil.changePrefix(endpoint, "/", "");
        if (!this.multiple) {
            return new String[] { path };
        }
        return this.tenants.keySet().stream().sorted().map(id -> OAUTH_METADATA.equals(path)
                ? "/" + path + this.root + id
                : id + "/" + path).toArray(String[]::new);
    }

    public void select(RoutingContext context) {
        if (!this.multiple) {
            context.next();
            return;
        }
        String path = context.normalizedPath();
        String id;
        String endpoint;
        // RFC 8414 inserts .well-known before the entire issuer path, including the HTTP root.
        String metadataPrefix = "/" + OAUTH_METADATA + this.root;
        if (path.startsWith(metadataPrefix)) {
            id = path.substring(metadataPrefix.length());
            endpoint = "/" + OAUTH_METADATA;
        } else {
            if (!path.startsWith(this.root)) {
                context.next();
                return;
            }
            String relative = path.substring(this.root.length());
            int slash = relative.indexOf('/');
            if (slash < 1) {
                if (this.endpoints.contains("/" + relative)) {
                    context.response().setStatusCode(404).end();
                } else {
                    context.next();
                }
                return;
            }
            id = relative.substring(0, slash);
            endpoint = relative.substring(slash);
            if (!this.endpoints.contains(endpoint) && this.endpoints.contains("/" + relative)) {
                context.response().setStatusCode(404).end();
                return;
            }
        }
        if (!this.endpoints.contains(endpoint)) {
            context.next();
            return;
        }
        AuthorizationServerSettings selected = this.tenants.get(id);
        if (selected == null || !context.request().path().equals(path)) {
            context.response().setStatusCode(404).end();
            return;
        }
        context.put(PROTOCOL_PATH, this.root + StringUtil.changePrefix(endpoint, "/", ""));
        context.put(CurrentAuthorizationServerContext.ATTRIBUTE, selected);
        ContextLocals.put(CurrentAuthorizationServerContext.ATTRIBUTE, selected);
        context.next();
    }

    /** Used by authentication mechanisms after issuer selection; never rewrites the incoming request. */
    public static String protocolPath(RoutingContext context) {
        String path = context.get(PROTOCOL_PATH);
        return path == null ? context.normalizedPath() : path;
    }
}

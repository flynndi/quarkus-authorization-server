package io.quarkiverse.authorization.server.runtime.tenant;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.tenant.AuthorizationServerTenant;
import io.smallrye.common.annotation.Identifier;

/** Resolves all configured CDI components at startup; no fallback to another tenant or to global storage. */
@Singleton
public final class AuthorizationServerTenantRegistry {
    private final Map<String, AuthorizationServerTenant> tenants;
    private final Map<String, AuthorizationServerKeyManager> keys;
    private final AuthorizationServerContext context;

    @Inject
    public AuthorizationServerTenantRegistry(AuthorizationServerEndpoints endpoints, AuthorizationServerContext context,
            @Any Instance<AuthorizationServerTenant> beans, AuthorizationServerOidcConfig oidc) {
        this.context = context;
        Map<String, AuthorizationServerTenant> tenants = new LinkedHashMap<>();
        Map<String, AuthorizationServerKeyManager> keys = new LinkedHashMap<>();
        endpoints.tenants().forEach((id, settings) -> {
            var selected = beans.select(Identifier.Literal.of(id));
            if (!selected.isResolvable()) {
                throw new IllegalStateException("Expected one AuthorizationServerTenant bean with @Identifier: " + id);
            }
            AuthorizationServerTenant tenant = selected.get();
            if (tenants.values().stream().anyMatch(existing -> existing.clients() == tenant.clients()
                    || existing.authorizations() == tenant.authorizations() || existing.consents() == tenant.consents())) {
                throw new IllegalStateException("Each issuer must supply distinct repository/service instances: " + id);
            }
            tenants.put(settings.getIssuer(), tenant);
            var manager = new AuthorizationServerKeyManager(tenant.signingKeys());
            if (oidc.enabled() && !manager.getSigningAlgorithms().contains(SignatureAlgorithm.RS256)) {
                throw new IllegalStateException("OpenID Connect requires an RS256 signing private key for issuer: " + id);
            }
            keys.put(settings.getIssuer(), manager);
        });
        this.tenants = Map.copyOf(tenants);
        this.keys = Map.copyOf(keys);
    }

    public AuthorizationServerTenant current() {
        return tenant(this.context.getIssuer());
    }

    /** Explicit issuer lookup for callers without a protocol request context; never creates components. */
    public AuthorizationServerTenant tenant(String issuer) {
        AuthorizationServerTenant tenant = this.tenants.get(issuer);
        if (tenant == null) {
            throw new IllegalStateException("Unknown authorization server issuer");
        }
        return tenant;
    }

    public AuthorizationServerKeyManager currentKeys() {
        return keys(this.context.getIssuer());
    }

    /** Returns the manager initialized at startup, without loading the tenant key source again. */
    public AuthorizationServerKeyManager keys(String issuer) {
        AuthorizationServerKeyManager keys = this.keys.get(issuer);
        if (keys == null) {
            throw new IllegalStateException("Unknown authorization server issuer");
        }
        return keys;
    }
}

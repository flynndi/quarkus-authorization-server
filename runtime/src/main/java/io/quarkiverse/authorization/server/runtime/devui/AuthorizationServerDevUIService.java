package io.quarkiverse.authorization.server.runtime.devui;

import java.util.List;

import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints;
import io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerTenantRegistry;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.runtime.token.ConfiguredAuthorizationServerKeySource;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;
import io.quarkus.arc.Arc;
import io.quarkus.arc.ClientProxy;
import io.quarkus.arc.InjectableBean;
import io.quarkus.runtime.util.StringUtil;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.VertxHttpConfig;

/** Read-only projection registered as a CDI bean by Quarkus Dev UI, never by application bean discovery. */
public class AuthorizationServerDevUIService {
    private final AuthorizationServerSettings settings;
    private final AuthorizationServerEndpoints endpoints;
    private final VertxHttpBuildTimeConfig httpBuild;
    private final VertxHttpConfig http;
    private final AuthorizationServerRuntimeConfig config;

    @Inject
    public AuthorizationServerDevUIService(AuthorizationServerSettings settings, AuthorizationServerEndpoints endpoints,
            VertxHttpBuildTimeConfig httpBuild, VertxHttpConfig http, AuthorizationServerRuntimeConfig config) {
        this.settings = settings;
        this.endpoints = endpoints;
        this.httpBuild = httpBuild;
        this.http = http;
        this.config = config;
    }

    /** Called by qwc-authorization-server-overview.js through the Dev UI JSON-RPC provider. */
    public Overview getOverview(String tenantId) {
        boolean multiple = this.settings.isMultipleIssuersAllowed();
        List<String> tenantIds = this.endpoints.tenants().keySet().stream().sorted().toList();
        AuthorizationServerSettings selected;
        if (multiple) {
            if (tenantId == null || tenantId.isEmpty()) {
                return new Overview(true, tenantIds, null, null, Status.SELECT_TENANT, login(), null);
            }
            // Dev UI requests have no protocol tenant context. Resolve only the explicitly selected tenant.
            selected = this.endpoints.tenants().get(tenantId);
        } else {
            selected = tenantId == null || tenantId.isEmpty() ? this.settings : null;
        }
        if (selected == null) {
            return new Overview(multiple, tenantIds, tenantId, null, Status.UNKNOWN_TENANT, login(), null);
        }
        String issuer = selected.getIssuer();
        Status status = issuer == null || issuer.isBlank() ? Status.ISSUER_NOT_CONFIGURED : Status.READY;
        return new Overview(multiple, tenantIds, tenantId, issuer, status, login(), assembly(multiple, issuer));
    }

    private Login login() {
        if (!this.httpBuild.auth().form()) {
            return new Login(false, null, null, null, null, false, null);
        }
        var form = this.http.auth().form();
        // Form locations are server-absolute, not relative to quarkus.http.root-path.
        return new Login(true, form.loginPage().map(value -> "/" + StringUtil.changePrefix(value, "/", "")).orElse(null),
                "/" + StringUtil.changePrefix(form.postLocation(), "/", ""),
                form.errorPage().map(value -> "/" + StringUtil.changePrefix(value, "/", "")).orElse(null),
                form.landingPage().map(value -> "/" + StringUtil.changePrefix(value, "/", "")).orElse(null),
                form.httpOnlyCookie(), form.cookieSameSite().name());
    }

    private Assembly assembly(boolean multiple, String issuer) {
        if (multiple) {
            var registry = AuthorizationServerDevUIService.existing(AuthorizationServerTenantRegistry.class);
            if (registry == null) {
                return null;
            }
            var tenant = registry.tenant(issuer);
            return new Assembly(List.of(
                    AuthorizationServerDevUIService.component("Registered clients", tenant.clients()),
                    AuthorizationServerDevUIService.component("Authorizations", tenant.authorizations()),
                    AuthorizationServerDevUIService.component("Consents", tenant.consents())),
                    AuthorizationServerDevUIService.signing("TENANT_SOURCE",
                            AuthorizationServerDevUIService.component("Signing key source", tenant.signingKeys()),
                            registry.keys(issuer)));
        }
        var managerBean = AuthorizationServerDevUIService.bean(AuthorizationServerKeyManager.class);
        var sourceBean = AuthorizationServerDevUIService.bean(AuthorizationServerKeySource.class);
        boolean configured = sourceBean != null && sourceBean.getBeanClass() == ConfiguredAuthorizationServerKeySource.class;
        String source;
        Component provider;
        if (managerBean != null && managerBean.getBeanClass() != AuthorizationServerKeyManager.class) {
            // An application manager can use any source; global signing configuration is not evidence of its origin.
            source = "APPLICATION_MANAGER";
            provider = AuthorizationServerDevUIService.component("Signing key manager", managerBean);
        } else {
            source = configured ? (this.config.signing().keys().isEmpty()
                    && this.config.signing().privateKeyLocation().isEmpty() ? "EPHEMERAL" : "CONFIGURED_PEM")
                    : "APPLICATION_SOURCE";
            provider = AuthorizationServerDevUIService.component("Signing key source", sourceBean);
        }
        return new Assembly(List.of(
                AuthorizationServerDevUIService.component("Registered clients",
                        AuthorizationServerDevUIService.bean(RegisteredClientRepository.class)),
                AuthorizationServerDevUIService.component("Authorizations",
                        AuthorizationServerDevUIService.bean(OAuth2AuthorizationService.class)),
                AuthorizationServerDevUIService.component("Consents",
                        AuthorizationServerDevUIService.bean(OAuth2AuthorizationConsentService.class))),
                AuthorizationServerDevUIService.signing(source, provider,
                        AuthorizationServerDevUIService.existing(AuthorizationServerKeyManager.class)));
    }

    private static Signing signing(String source, Component provider, AuthorizationServerKeyManager manager) {
        if (manager == null) {
            return new Signing(source, provider, null, List.of(), false);
        }
        // Project only identifiers and algorithms from cached public JWKs, never serialize a manager or key object.
        List<Key> keys = manager.getPublicJwks().stream()
                .map(jwk -> new Key((String) jwk.get("kid"), (String) jwk.get("alg"))).toList();
        return new Signing(source, provider, manager.getKeyId(), keys, true);
    }

    private static <T> InjectableBean<T> bean(Class<T> type) {
        var selected = Arc.container().select(type);
        return selected.isResolvable() ? selected.getHandle().getBean() : null;
    }

    private static <T> T existing(Class<T> type) {
        var bean = AuthorizationServerDevUIService.bean(type);
        if (bean == null) {
            return null;
        }
        var context = Arc.container().getActiveContext(bean.getScope());
        // The one-argument Context.get never creates an instance. In particular, do not instantiate dependent producers.
        return context == null ? null : context.get(bean);
    }

    private static Component component(String role, InjectableBean<?> bean) {
        return bean == null ? new Component(role, null, "UNAVAILABLE", null, false)
                : new Component(role, bean.getBeanClass().getName(), bean.getKind().name(),
                        bean.getScope().getSimpleName(), bean.isDefaultBean());
    }

    private static Component component(String role, Object instance) {
        // Inspect a client proxy's metadata without creating its contextual instance.
        Class<?> type = instance instanceof ClientProxy proxy ? proxy.arc_bean().getBeanClass() : instance.getClass();
        return new Component(role, type.isSynthetic() ? "Application-supplied function" : type.getName(),
                "TENANT_COMPONENT", null, false);
    }

    public enum Status {
        READY,
        SELECT_TENANT,
        UNKNOWN_TENANT,
        ISSUER_NOT_CONFIGURED
    }

    /** Explicit allowlist: no configuration maps, component instances, key material or authentication state. */
    public record Overview(boolean multipleIssuers, List<String> tenantIds, String tenantId, String issuer, Status status,
            Login login, Assembly assembly) {
    }

    public record Login(boolean formEnabled, String loginPage, String postLocation, String errorPage, String landingPage,
            boolean httpOnlyCookie, String cookieSameSite) {
    }

    public record Assembly(List<Component> storage, Signing signing) {
    }

    /** For producer beans, className is the declaring class, not a guess at the produced implementation. */
    public record Component(String role, String className, String kind, String scope, boolean defaultBean) {
    }

    public record Signing(String source, Component provider, String activeKeyId, List<Key> keys, boolean initialized) {
    }

    public record Key(String keyId, String algorithm) {
    }
}

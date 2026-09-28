package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.vertx.http.runtime.PolicyMappingConfig;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.VertxHttpConfig;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.quarkus.vertx.http.runtime.security.ImmutablePathMatcher;
import io.quarkus.vertx.http.security.HttpSecurity;

/** Installed only with the default pages. Endpoint policies still decide whether an identity is required. */
public final class BrowserLoginSecurityConfiguration {
    @Inject
    DefaultLoginPage pages;
    @Inject
    AuthorizationServerEndpoints endpoints;
    @Inject
    AuthorizationServerSettings settings;
    @Inject
    AuthorizationServerOidcConfig oidc;
    @Inject
    VertxHttpConfig http;
    @Inject
    VertxHttpBuildTimeConfig buildTimeHttp;

    void configure(@Observes HttpSecurity security) {
        Map<String, Set<String>> paths = new LinkedHashMap<>();
        for (String path : this.pages.paths()) {
            // Only GET has a page handler. Other methods may fall through (or be Form's POST location).
            paths.put(path, Set.of());
        }
        for (String path : this.endpoints.paths(this.settings.getAuthorizationEndpoint())) {
            paths.put(path, Set.of("GET", "POST"));
        }
        for (String path : this.endpoints.paths(this.settings.getDeviceVerificationEndpoint())) {
            paths.put(path, Set.of("GET", "POST"));
        }
        if (this.oidc.enabled()) {
            for (String path : this.endpoints.paths(this.settings.getOidcLogoutEndpoint())) {
                paths.put(path, Set.of("GET", "POST"));
            }
        }
        // A broader API mechanism must not capture Quarkus Form's credential submission.
        paths.putIfAbsent(this.pages.postPath(), Set.of("POST"));
        this.validateMechanisms(paths);
        paths.forEach((path, methods) -> {
            var permission = security.path(path);
            if (!methods.isEmpty()) {
                permission.methods(methods.toArray(String[]::new));
            }
            permission.form().permit();
        });
    }

    private void validateMechanisms(Map<String, Set<String>> paths) {
        String root = this.buildTimeHttp.rootPath();
        String rootPrefix = root.endsWith("/") ? root : root + "/";
        Map<String, Set<String>> absolutePaths = new LinkedHashMap<>();
        paths.forEach((path, methods) -> absolutePaths.put(
                HttpSecurityUtils.normalizePath(path.startsWith("/") ? path : rootPrefix + path), methods));
        this.http.auth().permissions().forEach((name, permission) -> {
            if (!permission.enabled().orElse(true) || permission.appliesTo() != PolicyMappingConfig.AppliesTo.ALL
                    || permission.authMechanism().isEmpty() || permission.authMechanism().get().equals(Set.of("form"))) {
                return;
            }
            for (String configuredPath : permission.paths().orElseGet(List::of)) {
                String path = configuredPath.trim();
                path = HttpSecurityUtils.normalizePath(path.startsWith("/") ? path : rootPrefix + path);
                // Ordinary wildcard rules lose to our exact paths. Shared rules still select a mechanism.
                var matcher = ImmutablePathMatcher.<Boolean> builder().addPath(path, true).build();
                for (var browser : absolutePaths.entrySet()) {
                    if ((path.equals(browser.getKey())
                            || permission.shared() && Boolean.TRUE.equals(matcher.match(browser.getKey()).getValue()))
                            && (browser.getValue().isEmpty() || permission.methods().isEmpty()
                                    || permission.methods().get().stream().anyMatch(browser.getValue()::contains))) {
                        throw new ConfigurationException("quarkus.http.auth.permission.\"" + name
                                + "\".auth-mechanism conflicts with the default Form login at " + browser.getKey()
                                + "; select only form or disable quarkus.authorization-server.default-login-page-enabled");
                    }
                }
            }
        });
    }
}

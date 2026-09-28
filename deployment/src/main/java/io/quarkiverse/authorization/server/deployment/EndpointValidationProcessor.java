package io.quarkiverse.authorization.server.deployment;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerClientRegistrationConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkus.arc.deployment.ValidationPhaseBuildItem.ValidationErrorBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.vertx.http.deployment.HttpRootPathBuildItem;

/** Diagnoses conflicts between the extension's enabled protocol endpoints during augmentation. */
@BuildSteps(onlyIf = AuthorizationServerProcessor.IsEnabled.class)
class EndpointValidationProcessor {
    @BuildStep
    ValidationErrorBuildItem validateEndpoints(AuthorizationServerBuildTimeConfig config,
            AuthorizationServerOidcConfig oidc, AuthorizationServerClientRegistrationConfig registration,
            HttpRootPathBuildItem root) {
        try {
            EndpointValidationProcessor.validate(config, oidc, registration, root);
            return null;
        } catch (ConfigurationException exception) {
            return new ValidationErrorBuildItem(exception);
        }
    }

    static void validate(AuthorizationServerBuildTimeConfig config, AuthorizationServerOidcConfig oidc,
            AuthorizationServerClientRegistrationConfig registration, HttpRootPathBuildItem root) {
        if (!config.enabled()) {
            return;
        }
        List<AuthorizationServerEndpoint> endpoints = AuthorizationServerEndpoint.configuredEndpoints(config, oidc,
                registration, root);
        for (int i = 0; i < endpoints.size(); i++) {
            AuthorizationServerEndpoint left = endpoints.get(i);
            for (int j = i + 1; j < endpoints.size(); j++) {
                AuthorizationServerEndpoint right = endpoints.get(j);
                Set<String> methods = new TreeSet<>(left.methods().contains("*") ? right.methods() : left.methods());
                if (!right.methods().contains("*")) {
                    methods.retainAll(right.methods());
                }
                if (!methods.isEmpty() && EndpointValidationProcessor.overlaps(left.path(), right.path())) {
                    Set<String> keys = new TreeSet<>();
                    if (left.name().startsWith("quarkus."))
                        keys.add(left.name());
                    if (right.name().startsWith("quarkus."))
                        keys.add(right.name());
                    throw new ConfigurationException("Authorization Server endpoint conflict: " + left.name()
                            + " (" + left.path() + ") and " + right.name() + " (" + right.path()
                            + ") both handle " + String.join(", ", methods), keys);
                }
            }
        }
    }

    private static boolean overlaps(String left, String right) {
        String[] first = left.split("/");
        String[] second = right.split("/");
        if (first.length != second.length)
            return false;
        for (int i = 0; i < first.length; i++) {
            // Tenant IDs follow AuthorizationServerEndpoints' allowlist; .well-known cannot be an issuer.
            boolean firstIssuer = first[i].equals(":issuer") && second[i].matches("[A-Za-z0-9_-]+");
            boolean secondIssuer = second[i].equals(":issuer") && first[i].matches("[A-Za-z0-9_-]+");
            if (!first[i].equals(second[i]) && !firstIssuer && !secondIssuer)
                return false;
        }
        return true;
    }

}

package io.quarkiverse.authorization.server.runtime.config;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;

/**
 * Optional OpenID Connect support, fixed when the application is built.
 */
@ConfigMapping(prefix = "quarkus.authorization-server.oidc")
@ConfigRoot(phase = ConfigPhase.BUILD_AND_RUN_TIME_FIXED)
public interface AuthorizationServerOidcConfig {

    /**
     * Enables OpenID Connect Authorization Code requests, Provider Configuration, UserInfo and Logout.
     */
    @WithDefault("false")
    boolean enabled();

    /** Enables protected dynamic client registration and configuration reads; requires OIDC to be enabled. */
    @WithName("client-registration.enabled")
    @WithDefault("false")
    boolean clientRegistrationEnabled();
}

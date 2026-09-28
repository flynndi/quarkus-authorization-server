package io.quarkiverse.authorization.server.runtime.config;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/** Optional RFC 7591 registration; independent of OIDC registration/configuration reads. */
@ConfigMapping(prefix = "quarkus.authorization-server.client-registration")
@ConfigRoot(phase = ConfigPhase.BUILD_AND_RUN_TIME_FIXED)
public interface AuthorizationServerClientRegistrationConfig {
    /** Install the OAuth client registration endpoint. */
    @WithDefault("false")
    boolean enabled();

    /** Allow registration without an initial access token at the OAuth endpoint only. */
    @WithDefault("false")
    boolean openRegistrationAllowed();
}

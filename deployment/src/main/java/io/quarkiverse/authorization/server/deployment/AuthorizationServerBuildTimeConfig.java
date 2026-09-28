package io.quarkiverse.authorization.server.deployment;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithConverter;
import io.smallrye.config.WithDefault;

/**
 * Build-time configuration for the authorization server.
 */
@ConfigMapping(prefix = "quarkus.authorization-server")
@ConfigRoot(phase = ConfigPhase.BUILD_TIME)
public interface AuthorizationServerBuildTimeConfig {

    /**
     * Whether the authorization server extension is enabled.
     * <p>
     * When disabled, the extension does not install its fixed endpoints or security beans.
     */
    @WithDefault("true")
    boolean enabled();

    /** Install issuer-prefixed protocol endpoints. Issuers and tenant components must be explicitly configured. */
    @WithDefault("false")
    boolean multipleIssuersAllowed();

    /**
     * Install the default login/error pages and select Quarkus Form Authentication for browser endpoints.
     * Requires {@code quarkus.http.auth.form.enabled=true}. Password authentication and browser
     * session handling remain the responsibility of Quarkus Security and the application's identity providers.
     * Supplies overridable Form defaults for the landing page, HttpOnly and SameSite cookies.
     * Disable this option when the application supplies its own login integration.
     */
    @WithDefault("false")
    boolean defaultLoginPageEnabled();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/authorize")
    String authorizationEndpoint();

    /** Install the optional RFC 9126 PAR endpoint and its discovery metadata. */
    @WithDefault("false")
    boolean pushedAuthorizationRequestsEnabled();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/par")
    String pushedAuthorizationRequestEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/device_authorization")
    String deviceAuthorizationEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/device_verification")
    String deviceVerificationEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/token")
    String tokenEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/jwks")
    String jwkSetEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/revoke")
    String tokenRevocationEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/introspect")
    String tokenIntrospectionEndpoint();

    /** Path of the independently enabled OAuth client registration endpoint. */
    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/oauth2/register")
    String clientRegistrationEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/connect/register")
    String oidcClientRegistrationEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/userinfo")
    String oidcUserInfoEndpoint();

    @WithConverter(EndpointPathConverter.class)
    @WithDefault("/connect/logout")
    String oidcLogoutEndpoint();

}

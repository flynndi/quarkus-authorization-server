package io.quarkiverse.authorization.server.runtime.web;

import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.authorization.server.runtime.client.web.OAuth2ClientAuthenticationMechanism;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.vertx.http.security.HttpSecurity;

/**
 * Selects OAuth 2.0 client authentication for protected Authorization Server endpoints.
 */
public final class OAuth2TokenEndpointSecurityConfiguration {

    private final AuthorizationServerSettings authorizationServerSettings;

    @Inject
    public OAuth2TokenEndpointSecurityConfiguration(AuthorizationServerSettings authorizationServerSettings) {
        this.authorizationServerSettings = authorizationServerSettings;
    }

    @Inject
    io.quarkiverse.authorization.server.runtime.tenant.AuthorizationServerEndpoints endpoints;

    void configure(@Observes HttpSecurity httpSecurity) {
        // HttpSecurity resolves relative paths against quarkus.http.root-path.
        String[] tokenEndpoint = this.endpoints.paths(this.authorizationServerSettings.getTokenEndpoint());
        String[] tokenIntrospectionEndpoint = this.endpoints
                .paths(this.authorizationServerSettings.getTokenIntrospectionEndpoint());
        String[] tokenRevocationEndpoint = this.endpoints.paths(this.authorizationServerSettings.getTokenRevocationEndpoint());
        String[] deviceAuthorizationEndpoint = this.endpoints
                .paths(this.authorizationServerSettings.getDeviceAuthorizationEndpoint());
        httpSecurity.path(tokenEndpoint).permit()
                .post(tokenEndpoint)
                .authenticatedWith(OAuth2ClientAuthenticationMechanism.AUTHENTICATION_SCHEME);
        httpSecurity.path(tokenIntrospectionEndpoint).permit()
                .post(tokenIntrospectionEndpoint)
                .authenticatedWith(OAuth2ClientAuthenticationMechanism.AUTHENTICATION_SCHEME);
        httpSecurity.path(tokenRevocationEndpoint).permit()
                .post(tokenRevocationEndpoint)
                .authenticatedWith(OAuth2ClientAuthenticationMechanism.AUTHENTICATION_SCHEME);
        httpSecurity.path(deviceAuthorizationEndpoint).permit()
                .post(deviceAuthorizationEndpoint)
                .authenticatedWith(OAuth2ClientAuthenticationMechanism.AUTHENTICATION_SCHEME);
        String par = this.authorizationServerSettings.getPushedAuthorizationRequestEndpoint();
        if (par != null) {
            String[] path = this.endpoints.paths(par);
            httpSecurity.path(path).permit().post(path)
                    .authenticatedWith(OAuth2ClientAuthenticationMechanism.AUTHENTICATION_SCHEME);
        }
        httpSecurity.get(this.endpoints.paths(this.authorizationServerSettings.getJwkSetEndpoint())).permit();
        httpSecurity.get(this.endpoints.paths(OAuth2AuthorizationServerMetadataEndpointHandler.DEFAULT_METADATA_ENDPOINT_PATH))
                .permit();
    }
}

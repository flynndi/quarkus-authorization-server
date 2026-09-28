package io.quarkiverse.authorization.server.runtime.oidc.web;

import java.util.List;

import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationResponseType;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.metadata.OAuth2AuthorizationServerMetadataClaimNames;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcProviderConfiguration;
import io.quarkiverse.authorization.server.oidc.OidcProviderMetadataCustomizer;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionVerifier;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerOidcConfig;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.oidc.http.converter.OidcProviderConfigurationHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkus.arc.All;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;
import io.vertx.core.Handler;
import io.vertx.core.http.ClientAuth;
import io.vertx.ext.web.RoutingContext;

/** Vert.x handler that publishes the enabled OpenID Provider configuration and discovery metadata. */
@Singleton
public final class OidcProviderConfigurationEndpointHandler implements Handler<RoutingContext> {

    public static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_PATH = ".well-known/openid-configuration";

    private final AuthorizationServerContext serverContext;
    private final AuthorizationServerKeyManager keyManager;
    private final List<String> dpopSigningAlgorithms;
    private final boolean tlsClientAuthenticationEnabled;
    private final boolean clientRegistrationEnabled;
    private final OidcProviderMetadataCustomizer providerConfigurationCustomizer;
    private final OidcProviderConfigurationHttpMessageConverter providerConfigurationConverter;
    private final OAuth2ErrorHttpMessageConverter errorConverter;

    private final ProtocolExecutor executor;

    @Inject
    public OidcProviderConfigurationEndpointHandler(
            AuthorizationServerContext serverContext,
            AuthorizationServerKeyManager keyManager,
            AuthorizationServerOidcConfig oidcConfig,
            AuthorizationServerRuntimeConfig runtimeConfig,
            VertxHttpBuildTimeConfig httpConfig,
            @All @Default List<OidcProviderMetadataCustomizer> providerConfigurationCustomizers,
            ProtocolExecutor executor,
            OidcProviderConfigurationHttpMessageConverter providerConfigurationConverter,
            OAuth2ErrorHttpMessageConverter errorConverter) {
        var providerConfigurationCustomizersSnapshot = List.copyOf(providerConfigurationCustomizers);

        this.serverContext = serverContext;
        this.keyManager = keyManager;
        this.tlsClientAuthenticationEnabled = httpConfig.tlsClientAuth() != ClientAuth.NONE;
        this.dpopSigningAlgorithms = runtimeConfig.dpop().proofAlgorithms().stream()
                .map(SignatureAlgorithm::getName)
                .sorted()
                .toList();
        // OpenID Connect Discovery requires RS256, irrespective of the active access-token
        // algorithm.
        if (!serverContext.isMultipleIssuersAllowed()
                && !keyManager.getSigningAlgorithms().contains(SignatureAlgorithm.RS256)) {
            throw new IllegalStateException("OpenID Connect requires an RS256 signing private key");
        }
        this.providerConfigurationCustomizer = context -> providerConfigurationCustomizersSnapshot.forEach(
                policy -> policy.customize(context));
        this.executor = executor;
        this.providerConfigurationConverter = providerConfigurationConverter;
        this.errorConverter = errorConverter;
        this.clientRegistrationEnabled = oidcConfig.clientRegistrationEnabled();
    }

    @Override
    public void handle(RoutingContext context) {
        String issuer = this.serverContext.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            context.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code());
            this.errorConverter.write(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), context.response());
            return;
        }
        this.executor
                .execute(
                        context,
                        () -> {
                            OidcProviderConfiguration.Builder configuration = OidcProviderConfiguration.builder()
                                    .issuer(issuer)
                                    .authorizationEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.serverContext.getAuthorizationServerSettings()
                                                            .getAuthorizationEndpoint()))
                                    .deviceAuthorizationEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.serverContext.getAuthorizationServerSettings()
                                                            .getDeviceAuthorizationEndpoint()))
                                    .tokenEndpoint(
                                            asUrl(issuer,
                                                    this.serverContext.getAuthorizationServerSettings().getTokenEndpoint()))
                                    .jwkSetUrl(
                                            asUrl(
                                                    issuer,
                                                    this.serverContext.getAuthorizationServerSettings().getJwkSetEndpoint()))
                                    .userInfoEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.serverContext.getAuthorizationServerSettings()
                                                            .getOidcUserInfoEndpoint()))
                                    .endSessionEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.serverContext.getAuthorizationServerSettings()
                                                            .getOidcLogoutEndpoint()))
                                    .tokenEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                                                    .getValue())
                                    .tokenEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_POST
                                                    .getValue())
                                    .tokenEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
                                    .tokenEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue())
                                    .tokenEndpointAuthenticationSigningAlgorithms(
                                            algorithms -> algorithms.addAll(JwtClientAssertionVerifier.SUPPORTED_ALGORITHMS))
                                    .tokenEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.NONE.getValue())
                                    .responseType(
                                            OAuth2AuthorizationResponseType.CODE.getValue())
                                    .grantType(
                                            AuthorizationGrantType.AUTHORIZATION_CODE
                                                    .getValue())
                                    .grantType(
                                            AuthorizationGrantType.CLIENT_CREDENTIALS
                                                    .getValue())
                                    .grantType(
                                            AuthorizationGrantType.REFRESH_TOKEN.getValue())
                                    .grantType(AuthorizationGrantType.PASSWORD.getValue())
                                    .grantType(
                                            AuthorizationGrantType.DEVICE_CODE.getValue())
                                    .grantType(
                                            AuthorizationGrantType.TOKEN_EXCHANGE
                                                    .getValue())
                                    .tokenIntrospectionEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.serverContext.getAuthorizationServerSettings()
                                                            .getTokenIntrospectionEndpoint()))
                                    .tokenIntrospectionEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                                                    .getValue())
                                    .tokenIntrospectionEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_POST
                                                    .getValue())
                                    .tokenIntrospectionEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
                                    .tokenIntrospectionEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue())
                                    .tokenIntrospectionEndpointAuthenticationSigningAlgorithms(
                                            algorithms -> algorithms.addAll(JwtClientAssertionVerifier.SUPPORTED_ALGORITHMS))
                                    .tokenRevocationEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.serverContext.getAuthorizationServerSettings()
                                                            .getTokenRevocationEndpoint()))
                                    .tokenRevocationEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                                                    .getValue())
                                    .tokenRevocationEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_POST
                                                    .getValue())
                                    .tokenRevocationEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
                                    .tokenRevocationEndpointAuthenticationMethod(
                                            ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue())
                                    .tokenRevocationEndpointAuthenticationSigningAlgorithms(
                                            algorithms -> algorithms.addAll(JwtClientAssertionVerifier.SUPPORTED_ALGORITHMS))
                                    .codeChallengeMethod("S256")
                                    .dPoPSigningAlgorithms(
                                            algorithms -> algorithms.addAll(this.dpopSigningAlgorithms))
                                    .subjectType("public")
                                    .scope(OidcScopes.OPENID);
                            this.keyManager.getSigningAlgorithms().forEach(
                                    algorithm -> configuration.idTokenSigningAlgorithm(
                                            algorithm.getName()));
                            if (this.clientRegistrationEnabled) {
                                configuration.clientRegistrationEndpoint(
                                        asUrl(
                                                issuer,
                                                this.serverContext.getAuthorizationServerSettings()
                                                        .getOidcClientRegistrationEndpoint()));
                            }
                            if (this.tlsClientAuthenticationEnabled) {
                                for (ClientAuthenticationMethod method : List.of(ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                                        ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)) {
                                    configuration.tokenEndpointAuthenticationMethod(method.getValue())
                                            .tokenIntrospectionEndpointAuthenticationMethod(method.getValue())
                                            .tokenRevocationEndpointAuthenticationMethod(method.getValue());
                                }
                            }
                            if (this.serverContext.getAuthorizationServerSettings()
                                    .getPushedAuthorizationRequestEndpoint() != null) {
                                configuration.claim(
                                        OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT,
                                        OidcProviderConfigurationEndpointHandler.asUrl(issuer, this.serverContext
                                                .getAuthorizationServerSettings().getPushedAuthorizationRequestEndpoint()));
                            }
                            this.providerConfigurationCustomizer.customize(configuration);
                            return configuration.build();
                        })
                .subscribe()
                .with(
                        result -> this.providerConfigurationConverter.write(
                                result, context.response()),
                        failure -> {
                            context.response().setStatusCode(500);
                            this.errorConverter.write(
                                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR),
                                    context.response());
                        });
    }

    private static String asUrl(String issuer, String endpoint) {
        return (issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer)
                + endpoint;
    }
}

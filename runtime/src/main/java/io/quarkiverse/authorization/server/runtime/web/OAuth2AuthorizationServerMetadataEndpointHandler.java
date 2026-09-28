package io.quarkiverse.authorization.server.runtime.web;

import java.util.List;

import jakarta.enterprise.inject.Default;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.metadata.AuthorizationServerMetadataCustomizer;
import io.quarkiverse.authorization.server.metadata.OAuth2AuthorizationServerMetadata;
import io.quarkiverse.authorization.server.metadata.OAuth2AuthorizationServerMetadataClaimNames;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.authentication.JwtClientAssertionVerifier;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2AuthorizationServerMetadataHttpMessageConverter;
import io.quarkiverse.authorization.server.runtime.http.converter.OAuth2ErrorHttpMessageConverter;
import io.quarkus.arc.All;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;
import io.vertx.core.Handler;
import io.vertx.core.http.ClientAuth;
import io.vertx.ext.web.RoutingContext;

/** Vert.x handler that publishes OAuth authorization server metadata for the installed capabilities. */
@Singleton
public final class OAuth2AuthorizationServerMetadataEndpointHandler
        implements Handler<RoutingContext> {

    public static final String DEFAULT_METADATA_ENDPOINT_PATH = ".well-known/oauth-authorization-server";

    private final AuthorizationServerContext authorizationServerContext;
    private final List<String> dpopSigningAlgorithms;
    private final boolean tlsClientAuthenticationEnabled;
    private final AuthorizationServerMetadataCustomizer metadataCustomizer;
    private final OAuth2AuthorizationServerMetadataHttpMessageConverter metadataConverter;
    private final OAuth2ErrorHttpMessageConverter errorResponseConverter;

    private final ProtocolExecutor executor;

    @Inject
    public OAuth2AuthorizationServerMetadataEndpointHandler(
            AuthorizationServerContext authorizationServerContext,
            AuthorizationServerRuntimeConfig runtimeConfig,
            VertxHttpBuildTimeConfig httpConfig,
            @All @Default List<AuthorizationServerMetadataCustomizer> metadataCustomizers,
            ProtocolExecutor executor,
            OAuth2AuthorizationServerMetadataHttpMessageConverter metadataConverter,
            OAuth2ErrorHttpMessageConverter errorResponseConverter) {
        var metadataCustomizersSnapshot = List.copyOf(metadataCustomizers);

        this.authorizationServerContext = authorizationServerContext;
        // Advertise the verifier's allow-list, independently of server token signing keys.
        this.tlsClientAuthenticationEnabled = httpConfig.tlsClientAuth() != ClientAuth.NONE;
        this.dpopSigningAlgorithms = runtimeConfig.dpop().proofAlgorithms().stream()
                .map(SignatureAlgorithm::getName)
                .sorted()
                .toList();
        this.metadataCustomizer = context -> metadataCustomizersSnapshot.forEach(policy -> policy.customize(context));
        this.executor = executor;
        this.metadataConverter = metadataConverter;
        this.errorResponseConverter = errorResponseConverter;
    }

    @Override
    public void handle(RoutingContext context) {
        String issuer = this.authorizationServerContext.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            context.response().setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code());
            this.errorResponseConverter.write(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), context.response());
            return;
        }

        this.executor
                .execute(
                        context,
                        () -> {
                            OAuth2AuthorizationServerMetadata.Builder metadata = OAuth2AuthorizationServerMetadata.builder()
                                    .issuer(issuer)
                                    .authorizationEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.authorizationServerContext.getAuthorizationServerSettings()
                                                            .getAuthorizationEndpoint()))
                                    .deviceAuthorizationEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.authorizationServerContext.getAuthorizationServerSettings()
                                                            .getDeviceAuthorizationEndpoint()))
                                    .tokenEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.authorizationServerContext.getAuthorizationServerSettings()
                                                            .getTokenEndpoint()))
                                    .jwkSetUrl(
                                            asUrl(
                                                    issuer,
                                                    this.authorizationServerContext.getAuthorizationServerSettings()
                                                            .getJwkSetEndpoint()))
                                    .grantType(AuthorizationGrantType.PASSWORD.getValue())
                                    .grantType(
                                            AuthorizationGrantType.AUTHORIZATION_CODE
                                                    .getValue())
                                    .grantType(
                                            AuthorizationGrantType.CLIENT_CREDENTIALS
                                                    .getValue())
                                    .grantType(
                                            AuthorizationGrantType.REFRESH_TOKEN.getValue())
                                    .grantType(
                                            AuthorizationGrantType.DEVICE_CODE.getValue())
                                    .grantType(
                                            AuthorizationGrantType.TOKEN_EXCHANGE
                                                    .getValue())
                                    .responseType("code")
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
                                    .tokenIntrospectionEndpoint(
                                            asUrl(
                                                    issuer,
                                                    this.authorizationServerContext.getAuthorizationServerSettings()
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
                                                    this.authorizationServerContext.getAuthorizationServerSettings()
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
                                            algorithms -> algorithms.addAll(this.dpopSigningAlgorithms));
                            if (this.tlsClientAuthenticationEnabled) {
                                for (ClientAuthenticationMethod method : List.of(ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                                        ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)) {
                                    metadata.tokenEndpointAuthenticationMethod(method.getValue())
                                            .tokenIntrospectionEndpointAuthenticationMethod(method.getValue())
                                            .tokenRevocationEndpointAuthenticationMethod(method.getValue());
                                }
                            }
                            if (this.authorizationServerContext.getAuthorizationServerSettings()
                                    .getPushedAuthorizationRequestEndpoint() != null) {
                                metadata.claim(
                                        OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT,
                                        OAuth2AuthorizationServerMetadataEndpointHandler.asUrl(issuer,
                                                this.authorizationServerContext.getAuthorizationServerSettings()
                                                        .getPushedAuthorizationRequestEndpoint()));
                            }
                            if (this.authorizationServerContext.getAuthorizationServerSettings()
                                    .getClientRegistrationEndpoint() != null) {
                                metadata.claim("registration_endpoint", OAuth2AuthorizationServerMetadataEndpointHandler.asUrl(
                                        issuer, this.authorizationServerContext.getAuthorizationServerSettings()
                                                .getClientRegistrationEndpoint()));
                            }
                            this.metadataCustomizer.customize(metadata);
                            return metadata.build();
                        })
                .subscribe()
                .with(
                        result -> this.metadataConverter.write(result, context.response()),
                        failure -> {
                            context.response().setStatusCode(500);
                            this.errorResponseConverter.write(
                                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR),
                                    context.response());
                        });
    }

    private static String asUrl(String issuer, String endpoint) {
        if (issuer.endsWith("/") && endpoint.startsWith("/")) {
            return issuer.substring(0, issuer.length() - 1) + endpoint;
        }
        if (!issuer.endsWith("/") && !endpoint.startsWith("/")) {
            return issuer + "/" + endpoint;
        }
        return issuer + endpoint;
    }
}

/*
 * Copyright 2020-2023 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
 * See the License for the specific language governing permissions and limitations under the License.
 */
package io.quarkiverse.authorization.server.runtime.oidc.converter;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationResponseType;
import io.quarkiverse.authorization.server.jose.jws.JwsAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.runtime.oidc.registration.OidcClientRegistrationMetadataValidator;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.settings.TokenSettings;

/**
 * Converts OIDC registration metadata to a newly issued client for persistence and response mapping.
 * The confidential client's secret is still plaintext here: the registration provider must
 * encode a copy for Basic/POST before saving it. HMAC assertions require the original secret.
 * Secrets are returned only in the initial registration response.
 */
public final class OidcClientRegistrationRegisteredClientConverter {

    private static final SecureRandom RANDOM = new SecureRandom();
    private final OidcClientRegistrationMetadataValidator validator;
    private final Consumer<ClientSettings.Builder> clientSettingsCustomizer;
    private final Consumer<TokenSettings.Builder> tokenSettingsCustomizer;

    public OidcClientRegistrationRegisteredClientConverter(Collection<SignatureAlgorithm> signingAlgorithms,
            Consumer<ClientSettings.Builder> clientSettingsCustomizer,
            Consumer<TokenSettings.Builder> tokenSettingsCustomizer) {
        this.validator = new OidcClientRegistrationMetadataValidator(signingAlgorithms);
        this.clientSettingsCustomizer = Objects.requireNonNull(
                clientSettingsCustomizer, "clientSettingsCustomizer cannot be null");
        this.tokenSettingsCustomizer = Objects.requireNonNull(
                tokenSettingsCustomizer, "tokenSettingsCustomizer cannot be null");
    }

    public RegisteredClient convert(OidcClientRegistration registration) {
        // The provider applies the replaceable request validator before invoking this converter.
        this.validator.validateSupportedMetadata(registration);
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(generateKey(32)).clientIdIssuedAt(Instant.now()).clientName(registration.getClientName());
        ClientAuthenticationMethod method = registration.getTokenEndpointAuthenticationMethod() == null
                ? ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                : new ClientAuthenticationMethod(registration.getTokenEndpointAuthenticationMethod());
        builder.clientAuthenticationMethod(method);
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)
                || ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)
                || ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(method)) {
            builder.clientSecret(OidcClientRegistrationRegisteredClientConverter.generateKey(48));
        }
        registration.getRedirectUris().forEach(builder::redirectUri);
        if (registration.getPostLogoutRedirectUris() != null) {
            registration.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
        }
        if (registration.getGrantTypes() != null) {
            registration.getGrantTypes().forEach(grant -> builder.authorizationGrantType(new AuthorizationGrantType(grant)));
        } else {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        }
        // Default response_types to code and register the authorization_code grant when needed.
        if (registration.getResponseTypes() == null
                || registration.getResponseTypes().contains(OAuth2AuthorizationResponseType.CODE.getValue())) {
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        }
        if (registration.getScopes() != null) {
            registration.getScopes().forEach(builder::scope);
        }
        ClientSettings.Builder clientSettings = ClientSettings.builder().requireProofKey(true)
                .requireAuthorizationConsent(true);
        if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(method)) {
            clientSettings.jwkSetUrl(registration.getJwkSetUrl().toString())
                    .tokenEndpointAuthenticationSigningAlgorithm(
                            registration.getTokenEndpointAuthenticationSigningAlgorithm() == null
                                    ? SignatureAlgorithm.RS256
                                    : JwsAlgorithm.from(registration.getTokenEndpointAuthenticationSigningAlgorithm()));
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(method)) {
            clientSettings.tokenEndpointAuthenticationSigningAlgorithm(
                    registration.getTokenEndpointAuthenticationSigningAlgorithm() == null
                            ? MacAlgorithm.HS256
                            : JwsAlgorithm.from(registration.getTokenEndpointAuthenticationSigningAlgorithm()));
        }
        if (ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.equals(method)) {
            clientSettings.jwkSetUrl(registration.getJwkSetUrl().toString());
        } else if (ClientAuthenticationMethod.TLS_CLIENT_AUTH.equals(method)) {
            clientSettings.x509CertificateSubjectDN(registration.getTlsClientAuthSubjectDn());
        }
        TokenSettings.Builder tokenSettings = TokenSettings.builder().idTokenSignatureAlgorithm(
                registration.getIdTokenSignedResponseAlgorithm() == null ? SignatureAlgorithm.RS256
                        : SignatureAlgorithm.from(registration.getIdTokenSignedResponseAlgorithm()));
        this.clientSettingsCustomizer.accept(clientSettings);
        this.tokenSettingsCustomizer.accept(tokenSettings);
        return builder.clientSettings(clientSettings.build()).tokenSettings(tokenSettings.build()).build();
    }

    private static String generateKey(int size) {
        byte[] bytes = new byte[size];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

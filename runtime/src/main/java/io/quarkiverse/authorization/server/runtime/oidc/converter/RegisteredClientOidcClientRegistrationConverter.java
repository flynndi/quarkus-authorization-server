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

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationResponseType;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.oidc.registration.ClientRegistrationMapper;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkus.arc.DefaultBean;

/**
 * Maps persisted client metadata to an OIDC registration response. The caller adds
 * registration_client_uri and registration_access_token only when those endpoints are available.
 * The supplied secret is copied; the client configuration retrieval service must remove it.
 */
@Singleton
@DefaultBean
public final class RegisteredClientOidcClientRegistrationConverter
        implements ClientRegistrationMapper {

    public OidcClientRegistration map(RegisteredClient client) {
        OidcClientRegistration.Builder builder = OidcClientRegistration.builder()
                .clientId(client.getClientId())
                .clientName(client.getClientName());
        if (client.getClientIdIssuedAt() != null) {
            builder.clientIdIssuedAt(client.getClientIdIssuedAt());
        }
        if (client.getClientSecret() != null) {
            builder.clientSecret(client.getClientSecret())
                    .clientSecretExpiresAt(client.getClientSecretExpiresAt());
        }
        client.getRedirectUris().forEach(builder::redirectUri);
        client.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
        client.getAuthorizationGrantTypes().forEach(grant -> builder.grantType(grant.getValue()));
        if (client.getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            builder.responseType(OAuth2AuthorizationResponseType.CODE.getValue());
        }
        client.getScopes().forEach(builder::scope);
        builder.tokenEndpointAuthenticationMethod(
                client.getClientAuthenticationMethods().iterator().next().getValue())
                .idTokenSignedResponseAlgorithm(
                        client.getTokenSettings().getIdTokenSignatureAlgorithm().getName());
        ClientSettings settings = client.getClientSettings();
        if (settings.getJwkSetUrl() != null) {
            builder.jwkSetUrl(settings.getJwkSetUrl());
        }
        if (settings.getTokenEndpointAuthenticationSigningAlgorithm() != null) {
            builder.tokenEndpointAuthenticationSigningAlgorithm(
                    settings.getTokenEndpointAuthenticationSigningAlgorithm().getName());
        }
        if (settings.getX509CertificateSubjectDN() != null) {
            builder.tlsClientAuthSubjectDn(settings.getX509CertificateSubjectDN());
        }
        return builder.build();
    }
}

/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.quarkiverse.authorization.server.runtime.oidc.userinfo;

import java.util.Objects;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.OidcUserInfo;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoContext;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoMapper;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.runtime.security.OAuth2AccessTokenAuthenticationRequest;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * Validates the authenticated token's current authorization and maps scope-filtered UserInfo
 * claims.
 */
@Singleton
public final class OidcUserInfoService {
    private final OAuth2AuthorizationService authorizationService;
    private final OidcUserInfoMapper userInfoMapper;

    @Inject
    public OidcUserInfoService(
            OAuth2AuthorizationService authorizationService, OidcUserInfoMapper userInfoMapper) {

        this.authorizationService = Objects.requireNonNull(authorizationService, "authorizationService cannot be null");
        this.userInfoMapper = Objects.requireNonNull(userInfoMapper, "userInfoMapper cannot be null");
    }

    /** Executes synchronously. The endpoint supplies the worker and CDI request context. */
    public OidcUserInfo userInfo(SecurityIdentity principal) {
        Objects.requireNonNull(principal, "principal cannot be null");
        TokenCredential credential = principal.getCredential(TokenCredential.class);
        if (principal.isAnonymous() || credential == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                credential.getToken(), OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null
                || authorization.getAccessToken() == null
                || !authorization.getAccessToken().isActive()
                || !credential
                        .getToken()
                        .equals(authorization.getAccessToken().getToken().getTokenValue())
                || !authorization.getPrincipalName().equals(principal.getPrincipal().getName())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        if (OAuth2AccessTokenAuthenticationRequest.DPOP.equals(credential.getType())) {
            // The IdentityProvider has checked ath/signature/replay. Recheck the persisted binding
            // without consuming the proof a second time or trusting a credential label alone.
            DPoPProof proof = principal.getAttribute(DPoPProof.class.getName());
            if (proof == null
                    || !DPoPTokenBinding.accessTokenThumbprint(authorization.getAccessToken())
                            .equals(proof.jwkThumbprint()))
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        } else if (!OAuth2AccessTokenAuthenticationRequest.BEARER.equals(credential.getType())
                || DPoPTokenBinding.isBound(authorization.getAccessToken())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
        if (!accessToken.getScopes().contains(OidcScopes.OPENID)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
        }
        if (authorization.getToken(OidcIdToken.class) == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
        }
        OidcUserInfoContext context = new OidcUserInfoContext(principal, accessToken, authorization);
        return Objects.requireNonNull(
                this.userInfoMapper.map(context), "userInfoMapper returned null");
    }
}

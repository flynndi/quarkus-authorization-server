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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.OidcScopes;
import io.quarkiverse.authorization.server.oidc.OidcUserInfo;
import io.quarkiverse.authorization.server.oidc.StandardClaimNames;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoContext;
import io.quarkiverse.authorization.server.oidc.userinfo.OidcUserInfoMapper;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkus.arc.DefaultBean;

/** Default scope-based UserInfo mapping policy. Instances contain no per-request state. */
@Singleton
@DefaultBean
public final class DefaultOidcUserInfoMapper implements OidcUserInfoMapper {

    private static final List<String> EMAIL_CLAIMS = Arrays.asList(StandardClaimNames.EMAIL, StandardClaimNames.EMAIL_VERIFIED);
    private static final List<String> PHONE_CLAIMS = Arrays.asList(
            StandardClaimNames.PHONE_NUMBER, StandardClaimNames.PHONE_NUMBER_VERIFIED);
    private static final List<String> PROFILE_CLAIMS = Arrays.asList(
            StandardClaimNames.NAME,
            StandardClaimNames.FAMILY_NAME,
            StandardClaimNames.GIVEN_NAME,
            StandardClaimNames.MIDDLE_NAME,
            StandardClaimNames.NICKNAME,
            StandardClaimNames.PREFERRED_USERNAME,
            StandardClaimNames.PROFILE,
            StandardClaimNames.PICTURE,
            StandardClaimNames.WEBSITE,
            StandardClaimNames.GENDER,
            StandardClaimNames.BIRTHDATE,
            StandardClaimNames.ZONEINFO,
            StandardClaimNames.LOCALE,
            StandardClaimNames.UPDATED_AT);

    @Override
    public OidcUserInfo map(OidcUserInfoContext authenticationContext) {
        OAuth2Authorization authorization = authenticationContext.authorization();
        OidcIdToken idToken = authorization.getToken(OidcIdToken.class).getToken();
        OAuth2AccessToken accessToken = authenticationContext.accessToken();
        Map<String, Object> scopeRequestedClaims = getClaimsRequestedByScope(idToken.getClaims(), accessToken.getScopes());

        return new OidcUserInfo(scopeRequestedClaims);
    }

    private static Map<String, Object> getClaimsRequestedByScope(
            Map<String, Object> claims, Set<String> requestedScopes) {
        Set<String> scopeRequestedClaimNames = new HashSet<>(32);
        scopeRequestedClaimNames.add(StandardClaimNames.SUB);

        if (requestedScopes.contains(OidcScopes.ADDRESS)) {
            scopeRequestedClaimNames.add(StandardClaimNames.ADDRESS);
        }
        if (requestedScopes.contains(OidcScopes.EMAIL)) {
            scopeRequestedClaimNames.addAll(EMAIL_CLAIMS);
        }
        if (requestedScopes.contains(OidcScopes.PHONE)) {
            scopeRequestedClaimNames.addAll(PHONE_CLAIMS);
        }
        if (requestedScopes.contains(OidcScopes.PROFILE)) {
            scopeRequestedClaimNames.addAll(PROFILE_CLAIMS);
        }
        if (requestedScopes.contains("groups")) {
            scopeRequestedClaimNames.add("groups");
        }
        if (requestedScopes.contains("perms")) {
            scopeRequestedClaimNames.add("perms");
        }

        Map<String, Object> requestedClaims = new HashMap<>(claims);
        requestedClaims
                .keySet()
                .removeIf(claimName -> !scopeRequestedClaimNames.contains(claimName));

        return requestedClaims;
    }
}

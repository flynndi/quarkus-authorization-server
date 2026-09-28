package io.quarkiverse.authorization.server.authorization;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.token.OAuth2DeviceCode;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkiverse.authorization.server.token.OAuth2UserCode;
import io.quarkus.arc.DefaultBean;

/**
 * In-memory authorization service intended for development and testing.
 */
@Singleton
@DefaultBean
public final class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final ConcurrentMap<String, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();

    public InMemoryOAuth2AuthorizationService() {
    }

    public InMemoryOAuth2AuthorizationService(OAuth2Authorization... authorizations) {
        this(Arrays.asList(authorizations));
    }

    public InMemoryOAuth2AuthorizationService(List<OAuth2Authorization> authorizations) {
        Objects.requireNonNull(authorizations, "authorizations cannot be null").forEach(authorization -> {
            Objects.requireNonNull(authorization, "authorization cannot be null");
            if (this.authorizations.containsKey(authorization.getId())) {
                throw new IllegalArgumentException(
                        "The authorization must be unique. Found duplicate identifier: " + authorization.getId());
            }
            this.authorizations.put(authorization.getId(), authorization);
        });
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Objects.requireNonNull(authorization, "authorization cannot be null");
        this.authorizations.put(authorization.getId(), authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Objects.requireNonNull(authorization, "authorization cannot be null");
        this.authorizations.remove(authorization.getId(), authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Arguments.requireNonBlank(id, "id");
        return this.authorizations.get(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Arguments.requireNonBlank(token, "token");
        for (OAuth2Authorization authorization : this.authorizations.values()) {
            if (matches(authorization, token, tokenType)) {
                return authorization;
            }
        }
        return null;
    }

    private static boolean matches(OAuth2Authorization authorization, String token, OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE))
                    || authorization.getToken(token) != null;
        }
        if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE));
        }
        if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return authorization.getAuthorizationCode() != null
                    && token.equals(authorization.getAuthorizationCode().getToken().getTokenValue());
        }
        if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return authorization.getAccessToken() != null
                    && token.equals(authorization.getAccessToken().getToken().getTokenValue());
        }
        if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return authorization.getRefreshToken() != null
                    && token.equals(authorization.getRefreshToken().getToken().getTokenValue());
        }
        if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            return authorization.getToken(OidcIdToken.class) != null
                    && token.equals(authorization.getToken(OidcIdToken.class).getToken().getTokenValue());
        }
        if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            return authorization.getToken(OAuth2UserCode.class) != null
                    && token.equals(authorization.getToken(OAuth2UserCode.class).getToken().getTokenValue());
        }
        if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            return authorization.getToken(OAuth2DeviceCode.class) != null
                    && token.equals(authorization.getToken(OAuth2DeviceCode.class).getToken().getTokenValue());
        }
        return false;
    }
}

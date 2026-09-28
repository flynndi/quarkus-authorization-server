package io.quarkiverse.authorization.server.oidc.userinfo;

import io.quarkiverse.authorization.server.oidc.OidcUserInfo;

/**
 * Maps UserInfo after the service validates the bearer authorization and scopes. A replacement CDI
 * bean is responsible for selecting the claims disclosed in the response.
 */
@FunctionalInterface
public interface OidcUserInfoMapper {
    OidcUserInfo map(OidcUserInfoContext context);
}

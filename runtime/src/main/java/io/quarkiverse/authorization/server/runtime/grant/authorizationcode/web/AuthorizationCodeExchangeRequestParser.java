package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.endpoint.PkceParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.AuthorizationCodeExchangeRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;

/**
 * Converts an Authorization Code token request into an {@link AuthorizationCodeExchangeRequest}.
 */
public final class AuthorizationCodeExchangeRequestParser {

    public AuthorizationCodeExchangeRequest parse(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        String grantType = parameters.get(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
            return null;
        }

        if (!(context.user() instanceof QuarkusHttpUser user)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        SecurityIdentity clientPrincipal = user.getSecurityIdentity();

        List<String> codeValues = parameters.getAll(OAuth2ParameterNames.CODE);
        if (codeValues.size() != 1 || codeValues.get(0).isBlank()) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.CODE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        String code = codeValues.get(0);

        List<String> redirectUriValues = parameters.getAll(OAuth2ParameterNames.REDIRECT_URI);
        if (redirectUriValues.size() > 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.REDIRECT_URI,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        String redirectUri = redirectUriValues.isEmpty() ? null : redirectUriValues.get(0);

        List<String> verifierValues = parameters.getAll(PkceParameterNames.CODE_VERIFIER);
        if (verifierValues.size() > 1
                || (!verifierValues.isEmpty() && verifierValues.get(0).isBlank())) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    PkceParameterNames.CODE_VERIFIER,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.GRANT_TYPE.equals(parameterName)
                    && !OAuth2ParameterNames.CLIENT_ID.equals(parameterName)
                    && !OAuth2ParameterNames.CODE.equals(parameterName)
                    && !OAuth2ParameterNames.REDIRECT_URI.equals(parameterName)) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new AuthorizationCodeExchangeRequest(
                code, clientPrincipal, redirectUri, additionalParameters);
    }
}

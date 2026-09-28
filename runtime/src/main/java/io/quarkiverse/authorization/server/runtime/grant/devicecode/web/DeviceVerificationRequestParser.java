package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceVerificationRequest;
import io.quarkiverse.authorization.server.grant.devicecode.OAuth2DeviceVerificationPage;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Converts a user-code submission into an {@link DeviceVerificationRequest}. */
public final class DeviceVerificationRequestParser {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final SecurityIdentity ANONYMOUS_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("anonymousUser"))
            .setAnonymous(true)
            .build();

    public DeviceVerificationRequest parse(RoutingContext context) {
        HttpMethod method = context.request().method();
        if (method != HttpMethod.GET && method != HttpMethod.POST) {
            return null;
        }
        MultiMap parameters = method == HttpMethod.GET
                ? context.queryParams()
                : context.request().formAttributes();
        // A malformed confirmation must reach the strict submission parser, not prepare a new state.
        if (parameters.get(OAuth2ParameterNames.STATE) != null
                || parameters.contains(OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME)
                || parameters.contains(OAuth2ParameterNames.CLIENT_ID)
                || parameters.get(OAuth2ParameterNames.USER_CODE) == null) {
            return null;
        }

        String userCode = parameters.get(OAuth2ParameterNames.USER_CODE);
        if (!OAuth2EndpointUtils.validateUserCode(userCode)
                || parameters.getAll(OAuth2ParameterNames.USER_CODE).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.USER_CODE, ERROR_URI);
        }

        SecurityIdentity principal = context.user() instanceof QuarkusHttpUser user
                ? user.getSecurityIdentity()
                : ANONYMOUS_PRINCIPAL;
        Map<String, Object> additionalParameters = new LinkedHashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.USER_CODE.equals(parameterName)) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new DeviceVerificationRequest(
                principal, OAuth2EndpointUtils.normalizeUserCode(userCode), additionalParameters);
    }
}

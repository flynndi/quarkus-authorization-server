package io.quarkiverse.authorization.server.runtime.grant.devicecode.web;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.devicecode.DeviceConsentSubmission;
import io.quarkiverse.authorization.server.grant.devicecode.OAuth2DeviceVerificationPage;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkiverse.authorization.server.runtime.web.authentication.OAuth2EndpointUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Parses a Device Authorization Consent into a {@link DeviceConsentSubmission}. */
public final class DeviceConsentSubmissionParser {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final SecurityIdentity ANONYMOUS_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("anonymousUser"))
            .setAnonymous(true)
            .build();

    public DeviceConsentSubmission parse(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        if (context.request().method() != HttpMethod.POST
                || (!parameters.contains(OAuth2ParameterNames.STATE)
                        && !parameters.contains(
                                OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME)
                        && !parameters.contains(OAuth2ParameterNames.CLIENT_ID))) {
            return null;
        }

        String clientId = parameters.get(OAuth2ParameterNames.CLIENT_ID);
        if (!Arguments.hasText(clientId) || parameters.getAll(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID, ERROR_URI);
        }

        SecurityIdentity principal = context.user() instanceof QuarkusHttpUser user
                ? user.getSecurityIdentity()
                : ANONYMOUS_PRINCIPAL;

        String userCode = parameters.get(OAuth2ParameterNames.USER_CODE);
        if (!OAuth2EndpointUtils.validateUserCode(userCode)
                || parameters.getAll(OAuth2ParameterNames.USER_CODE).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.USER_CODE, ERROR_URI);
        }

        String state = parameters.get(OAuth2ParameterNames.STATE);
        if (!Arguments.hasText(state) || parameters.getAll(OAuth2ParameterNames.STATE).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE, ERROR_URI);
        }

        String approved = parameters.get(OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME);
        if ((!"true".equals(approved) && !"false".equals(approved))
                || parameters.getAll(OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME,
                    ERROR_URI);
        }

        Set<String> scopes = Collections.emptySet();
        if (parameters.contains(OAuth2ParameterNames.SCOPE)) {
            scopes = new LinkedHashSet<>(parameters.getAll(OAuth2ParameterNames.SCOPE));
        }

        Map<String, Object> additionalParameters = new LinkedHashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.CLIENT_ID.equals(parameterName)
                    && !OAuth2ParameterNames.USER_CODE.equals(parameterName)
                    && !OAuth2ParameterNames.STATE.equals(parameterName)
                    && !OAuth2ParameterNames.SCOPE.equals(parameterName)
                    && !OAuth2DeviceVerificationPage.APPROVAL_PARAMETER_NAME.equals(
                            parameterName)) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new DeviceConsentSubmission(
                clientId,
                principal,
                OAuth2EndpointUtils.normalizeUserCode(userCode),
                state,
                Boolean.parseBoolean(approved),
                scopes,
                additionalParameters);
    }
}

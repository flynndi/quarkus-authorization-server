package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.quarkiverse.authorization.server.endpoint.OAuth2ParameterNames;
import io.quarkiverse.authorization.server.grant.authorizationcode.ConsentSubmission;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization.AuthorizationRequestException;
import io.quarkiverse.authorization.server.runtime.util.Arguments;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.web.RoutingContext;

/** Converts an Authorization Consent into an {@link ConsentSubmission}. */
public final class ConsentSubmissionParser {

    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final SecurityIdentity ANONYMOUS_PRINCIPAL = QuarkusSecurityIdentity.builder()
            .setPrincipal(new QuarkusPrincipal("anonymousUser"))
            .setAnonymous(true)
            .build();

    public ConsentSubmission parse(RoutingContext context) {
        MultiMap parameters = context.request().formAttributes();
        if (context.request().method() != HttpMethod.POST
                || parameters.contains(OAuth2ParameterNames.RESPONSE_TYPE)
                || parameters.contains(OAuth2ParameterNames.REQUEST_URI)) {
            return null;
        }

        String clientId = parameters.get(OAuth2ParameterNames.CLIENT_ID);
        if (!Arguments.hasText(clientId) || parameters.getAll(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
        }

        SecurityIdentity principal = context.user() instanceof QuarkusHttpUser user
                ? user.getSecurityIdentity()
                : ANONYMOUS_PRINCIPAL;

        String state = parameters.get(OAuth2ParameterNames.STATE);
        if (!Arguments.hasText(state) || parameters.getAll(OAuth2ParameterNames.STATE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        if (parameters.contains(ConsentSubmission.ACTION_PARAMETER)) {
            List<String> actions = parameters.getAll(ConsentSubmission.ACTION_PARAMETER);
            if (actions.size() != 1
                    || !(ConsentSubmission.APPROVE_ACTION.equals(actions.getFirst())
                            || ConsentSubmission.DENY_ACTION.equals(actions.getFirst()))) {
                ConsentSubmissionParser.throwError(
                        OAuth2ErrorCodes.INVALID_REQUEST, ConsentSubmission.ACTION_PARAMETER);
            }
        }

        Set<String> scopes = Collections.emptySet();
        if (parameters.contains(OAuth2ParameterNames.SCOPE)) {
            scopes = new LinkedHashSet<>(parameters.getAll(OAuth2ParameterNames.SCOPE));
        }

        Map<String, Object> additionalParameters = new LinkedHashMap<>();
        for (String parameterName : parameters.names()) {
            if (!OAuth2ParameterNames.CLIENT_ID.equals(parameterName)
                    && !OAuth2ParameterNames.STATE.equals(parameterName)
                    && !OAuth2ParameterNames.SCOPE.equals(parameterName)) {
                List<String> values = parameters.getAll(parameterName);
                additionalParameters.put(
                        parameterName,
                        values.size() == 1 ? values.get(0) : values.toArray(String[]::new));
            }
        }

        return new ConsentSubmission(
                authorizationUri(context),
                clientId,
                principal,
                state,
                scopes,
                additionalParameters);
    }

    private static String authorizationUri(RoutingContext context) {
        String absoluteUri = context.request().absoluteURI();
        int queryIndex = absoluteUri.indexOf('?');
        return queryIndex >= 0 ? absoluteUri.substring(0, queryIndex) : absoluteUri;
    }

    private static void throwError(String errorCode, String parameterName) {
        throw new AuthorizationRequestException(
                new OAuth2Error(
                        errorCode, "OAuth 2.0 Parameter: " + parameterName, DEFAULT_ERROR_URI),
                null);
    }
}

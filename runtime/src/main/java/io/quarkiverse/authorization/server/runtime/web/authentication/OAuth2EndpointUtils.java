package io.quarkiverse.authorization.server.runtime.web.authentication;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;
import io.quarkiverse.authorization.server.runtime.util.Arguments;

/**
 * Utility methods for the OAuth 2.0 protocol endpoints.
 */
public final class OAuth2EndpointUtils {

    public static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private OAuth2EndpointUtils() {
    }

    public static String normalizeUserCode(String userCode) {
        if (!Arguments.hasText(userCode)) {
            throw new IllegalArgumentException("userCode cannot be empty");
        }
        StringBuilder normalized = new StringBuilder(userCode.toUpperCase().replaceAll("[^A-Z\\d]+", ""));
        if (normalized.length() != 8) {
            throw new IllegalArgumentException(
                    "userCode must be exactly 8 alpha/numeric characters");
        }
        normalized.insert(4, '-');
        return normalized.toString();
    }

    public static boolean validateUserCode(String userCode) {
        return Arguments.hasText(userCode)
                && userCode.toUpperCase().replaceAll("[^A-Z\\d]+", "").length() == 8;
    }

    public static void throwError(String errorCode, String parameterName, String errorUri) {
        throw new OAuth2AuthenticationException(new OAuth2Error(
                errorCode,
                "OAuth 2.0 Parameter: " + parameterName,
                errorUri));
    }
}

package io.quarkiverse.authorization.server.model;

import java.io.Serial;
import java.io.Serializable;

/**
 * An OAuth 2.0 error.
 */
public class OAuth2Error implements Serializable {

    @Serial
    private static final long serialVersionUID = -2509129731547612161L;

    private final String errorCode;
    private final String description;
    private final String uri;

    public OAuth2Error(String errorCode) {
        this(errorCode, null, null);
    }

    public OAuth2Error(String errorCode, String description, String uri) {
        if (errorCode == null || errorCode.isBlank()) {
            throw new IllegalArgumentException("errorCode cannot be empty");
        }
        this.errorCode = errorCode;
        this.description = description;
        this.uri = uri;
    }

    public final String getErrorCode() {
        return this.errorCode;
    }

    public final String getDescription() {
        return this.description;
    }

    public final String getUri() {
        return this.uri;
    }

    @Override
    public String toString() {
        return "[" + getErrorCode() + "] " + (getDescription() != null ? getDescription() : "");
    }
}

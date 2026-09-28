package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.authorization;

import java.io.Serial;

import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2Error;

/** Protocol failure with an optional validated redirect target; never an authentication result. */
public final class AuthorizationRequestException extends OAuth2AuthenticationException {

    @Serial
    private static final long serialVersionUID = 8653054752822529360L;

    private final AuthorizationRedirect redirect;

    public AuthorizationRequestException(OAuth2Error error, AuthorizationRedirect redirect) {
        super(error);
        this.redirect = redirect;
    }

    public AuthorizationRedirect getRedirect() {
        return this.redirect;
    }
}

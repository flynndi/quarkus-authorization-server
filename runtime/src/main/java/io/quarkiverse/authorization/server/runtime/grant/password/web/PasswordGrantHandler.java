package io.quarkiverse.authorization.server.runtime.grant.password.web;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.grant.password.PasswordGrant;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * Adapts Password HTTP requests to asynchronous identity authentication and synchronous issuance.
 */
@Singleton
public final class PasswordGrantHandler implements TokenGrantHandler {
    private final ProtocolExecutor executor;
    private final PasswordGrantRequestParser parser = new PasswordGrantRequestParser();
    private final PasswordGrant grant;
    private final PasswordIdentityAuthenticator identities;

    @Inject
    public PasswordGrantHandler(
            PasswordGrant grant,
            PasswordIdentityAuthenticator identities,
            ProtocolExecutor executor) {
        this.executor = executor;
        this.grant = grant;
        this.identities = identities;
    }

    @Override
    public AuthorizationGrantType getGrantType() {
        return AuthorizationGrantType.PASSWORD;
    }

    @Override
    public Uni<TokenIssuanceResult> handle(RoutingContext context) {
        return Uni.createFrom()
                .deferred(
                        () -> {
                            var request = this.parser.parse(context);
                            if (request == null) {
                                throw new OAuth2AuthenticationException(
                                        OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
                            }
                            this.grant.validateClient(request);
                            // User authentication remains asynchronous; only signing/storage enter
                            // the worker scope.
                            return this.identities
                                    .authenticate(request, context)
                                    .onItem()
                                    .transformToUni(
                                            identity -> this.executor.execute(
                                                    context,
                                                    () -> this.grant.issueTokens(
                                                            request, identity)));
                        });
    }
}

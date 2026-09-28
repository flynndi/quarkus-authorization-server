package io.quarkiverse.authorization.server.runtime.grant.refreshtoken.web;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.grant.refreshtoken.RefreshTokenGrant;
import io.quarkiverse.authorization.server.runtime.web.ProtocolExecutor;
import io.quarkiverse.authorization.server.token.TokenIssuanceResult;
import io.quarkiverse.authorization.server.web.TokenGrantHandler;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/** Parses this grant and invokes its typed service within the Quarkus execution boundary. */
@Singleton
public final class RefreshTokenGrantHandler implements TokenGrantHandler {
    private final ProtocolExecutor executor;
    private final RefreshTokenRequestParser parser = new RefreshTokenRequestParser();
    private final RefreshTokenGrant service;

    @Inject
    public RefreshTokenGrantHandler(RefreshTokenGrant service, ProtocolExecutor executor) {
        this.executor = executor;
        this.service = service;
    }

    @Override
    public AuthorizationGrantType getGrantType() {
        return AuthorizationGrantType.REFRESH_TOKEN;
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
                            return this.executor.execute(
                                    context,
                                    () -> this.service.issueTokens(
                                            request,
                                            DPoPProofRequest.ifAvailable(context)));
                        });
    }
}

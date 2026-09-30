package io.quarkiverse.authorization.server.it.tokenexchange;

import java.util.Map;

import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;

/** Adds a test-only {@code may_act} delegation policy to one source client. */
@Singleton
public class TokenExchangeJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        if (AuthorizationGrantType.PASSWORD.equals(context.getAuthorizationGrantType())
                && TokenExchangeServerConfig.DELEGATED_SUBJECT_CLIENT.equals(
                        context.getRegisteredClient().getClientId())) {
            context.getClaims().claim("may_act", Map.of(
                    "iss", context.getAuthorizationServerContext().getIssuer(),
                    "sub", TokenExchangeServerConfig.ACTOR_CLIENT));
        }
    }
}

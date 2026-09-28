package io.quarkiverse.authorization.server.deployment;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.spec.JavaArchive;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.client.registration.OAuth2ClientRegistrationRequest;
import io.quarkiverse.authorization.server.client.registration.OAuth2ClientRegistrationRequestValidator;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkus.arc.Arc;
import io.quarkus.runtime.BlockingOperationControl;

public final class OAuthClientRegistrationTestSupport {
    static JavaArchive application(JavaArchive jar) {
        return ClientRegistrationTestApplication.baseApplication(jar).addClasses(OAuthClientRegistrationTestSupport.class,
                ScopePolicy.class);
    }

    static String initial(OAuth2AuthorizationService authorizations, RegisteredClientRepository clients, Set<String> scopes) {
        String value = UUID.randomUUID().toString();
        var client = clients.findByClientId("bootstrap");
        authorizations.save(OAuth2Authorization.withRegisteredClient(client).principalName(client.getClientId())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).authorizedScopes(scopes)
                .accessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, value, Instant.now(),
                        Instant.now().plusSeconds(300), scopes))
                .refreshToken(new io.quarkiverse.authorization.server.token.OAuth2RefreshToken("refresh-" + value,
                        Instant.now(), Instant.now().plusSeconds(300)))
                .build());
        return value;
    }

    @Singleton
    public static class ScopePolicy implements OAuth2ClientRegistrationRequestValidator {
        @Override
        public void validate(OAuth2ClientRegistrationRequest request) {
            org.junit.jupiter.api.Assertions.assertTrue(Arc.container().requestContext().isActive());
            org.junit.jupiter.api.Assertions.assertTrue(BlockingOperationControl.isBlockingAllowed());
            if (!Set.of("message.read").containsAll(request.scopes()))
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
    }
}

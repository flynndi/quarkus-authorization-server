package io.quarkiverse.authorization.server.runtime.client.authentication;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.context.AuthorizationServerContext;
import io.quarkiverse.authorization.server.jose.jws.JwsAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.MacAlgorithm;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.util.Arguments;

/** Verifies assertions with registered algorithms and keys, independently of HTTP and token grants. */
@Singleton
public final class JwtClientAssertionVerifier {
    // Allow bounded clock skew when validating client assertions.
    private static final int CLOCK_SKEW_SECONDS = 60;
    private static final int MAX_ASSERTION_LENGTH = 16_384;
    public static final List<String> SUPPORTED_ALGORITHMS = Stream.concat(
            Arrays.stream(SignatureAlgorithm.values()), Arrays.stream(MacAlgorithm.values()))
            .map(JwsAlgorithm::getName).toList();

    private final AuthorizationServerContext serverContext;
    private final ClientJwkSetCache keySets;

    @Inject
    public JwtClientAssertionVerifier(AuthorizationServerContext serverContext, ClientJwkSetCache keySets) {
        this.serverContext = serverContext;
        this.keySets = keySets;
    }

    public ClientAuthenticationMethod verify(RegisteredClient client, String assertion) {
        try {
            if (assertion == null || assertion.length() > MAX_ASSERTION_LENGTH
                    || !assertion.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            }
            JwsAlgorithm algorithm = client.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm();
            ClientAuthenticationMethod method;
            if (algorithm instanceof SignatureAlgorithm) {
                method = ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            } else if (algorithm instanceof MacAlgorithm) {
                method = ClientAuthenticationMethod.CLIENT_SECRET_JWT;
            } else {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            }
            if (!client.getClientAuthenticationMethods().contains(method)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
            }
            String issuer = Arguments.requireNonBlank(this.serverContext.getIssuer(), "issuer");
            String issuerBase = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
            var audiences = new java.util.ArrayList<>(java.util.List.of(issuer,
                    issuerBase + this.serverContext.getAuthorizationServerSettings().getTokenEndpoint(),
                    issuerBase + this.serverContext.getAuthorizationServerSettings().getTokenIntrospectionEndpoint(),
                    issuerBase + this.serverContext.getAuthorizationServerSettings().getTokenRevocationEndpoint()));
            if (this.serverContext.getAuthorizationServerSettings().getPushedAuthorizationRequestEndpoint() != null) {
                audiences.add(issuerBase
                        + this.serverContext.getAuthorizationServerSettings().getPushedAuthorizationRequestEndpoint());
            }
            JwtConsumerBuilder verifier = new JwtConsumerBuilder()
                    .setJwsAlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, algorithm.getName())
                    .setExpectedIssuer(client.getClientId())
                    .setExpectedSubject(client.getClientId())
                    .setExpectedAudience(audiences.toArray(String[]::new))
                    .setRequireExpirationTime()
                    .setAllowedClockSkewInSeconds(CLOCK_SKEW_SECONDS);
            if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(method)) {
                String location = client.getClientSettings().getJwkSetUrl();
                // Only repository-owned URLs are resolved. JWT jwk/jku/x5u headers never choose keys or URLs.
                HttpsJwksVerificationKeyResolver resolver = new HttpsJwksVerificationKeyResolver(this.keySets.get(location));
                resolver.setDisambiguateWithVerifySignature(true);
                verifier.setVerificationKeyResolver(resolver);
            } else {
                String secret = Arguments.requireNonBlank(client.getClientSecret(), "clientSecret");
                if (client.getClientSecretExpiresAt() != null
                        && !Instant.now().isBefore(client.getClientSecretExpiresAt())) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
                }
                // HMAC needs the original secret bytes; bcrypt verification cannot recover them.
                verifier.setVerificationKey(new HmacKey(secret.getBytes(StandardCharsets.UTF_8)));
            }
            verifier.build().processToClaims(assertion);
            return method;
        } catch (Exception exception) {
            // Do not propagate JWT contents, remote URLs, key material or library exception text.
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
    }

}

package io.quarkiverse.authorization.server.runtime.token;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.dpop.DPoPProof;
import io.quarkiverse.authorization.server.endpoint.OAuth2AuthorizationRequest;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.oidc.IdTokenClaimNames;
import io.quarkiverse.authorization.server.oidc.OidcIdToken;
import io.quarkiverse.authorization.server.oidc.endpoint.OidcParameterNames;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPTokenBinding;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.JwsHeader;
import io.quarkiverse.authorization.server.token.Jwt;
import io.quarkiverse.authorization.server.token.JwtClaimsSet;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2Token;
import io.quarkiverse.authorization.server.token.OAuth2TokenContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenGenerator;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import io.smallrye.jwt.build.JwtSignatureBuilder;

/**
 * Generates self-contained access tokens and OpenID Connect ID Tokens using SmallRye JWT Build.
 */
public final class JwtGenerator implements OAuth2TokenGenerator<OAuth2Token> {

    private final AuthorizationServerKeyManager keyManager;
    private final OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    public JwtGenerator(AuthorizationServerKeyManager keyManager,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        this.keyManager = keyManager;
        this.jwtCustomizer = jwtCustomizer;
    }

    @Override
    public Jwt generate(OAuth2TokenContext context) {
        boolean idToken = context.getTokenType() != null
                && OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue());
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) && !idToken) {
            return null;
        }
        RegisteredClient registeredClient = context.getRegisteredClient();
        if (!idToken && !OAuth2TokenFormat.SELF_CONTAINED.equals(registeredClient.getTokenSettings().getAccessTokenFormat())) {
            return null;
        }

        String issuer = context.getAuthorizationServerContext().getIssuer();
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException(
                    "quarkus.authorization-server.issuer must be configured");
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(idToken ? Duration.ofMinutes(30)
                : registeredClient.getTokenSettings().getAccessTokenTimeToLive());
        SignatureAlgorithm algorithm = this.keyManager.getAlgorithm();
        if (idToken) {
            algorithm = registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm();
            if (algorithm == null) {
                algorithm = SignatureAlgorithm.RS256;
            }
        }
        AuthorizationServerKeyManager.SigningKey signingKey = this.keyManager.getSigningKey(algorithm);

        JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(algorithm.getName()).keyId(signingKey.keyId()).type("JWT");
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(context.getPrincipal().getPrincipal().getName())
                .audience(List.of(registeredClient.getClientId()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString());
        if (!idToken) {
            claimsBuilder.notBefore(issuedAt);
            Set<String> authorizedScopes = context.getAuthorizedScopes();
            if (!authorizedScopes.isEmpty()) {
                claimsBuilder.claim("scope", authorizedScopes);
            }
        } else {
            claimsBuilder.claim(IdTokenClaimNames.AZP, registeredClient.getClientId());
            if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {
                OAuth2AuthorizationRequest request = context.getAuthorization()
                        .getAttribute(OAuth2AuthorizationRequest.class.getName());
                String nonce = (String) request.getAdditionalParameters().get(OidcParameterNames.NONCE);
                if (nonce != null && !nonce.isBlank()) {
                    claimsBuilder.claim(IdTokenClaimNames.NONCE, nonce);
                }
                SessionInformation session = context.getAuthorization().getAttribute(SessionInformation.class.getName());
                if (session != null) {
                    claimsBuilder.claim("sid", session.sessionId());
                    claimsBuilder.claim(IdTokenClaimNames.AUTH_TIME, session.authenticationTime());
                }
            } else if (AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType())) {
                OidcIdToken currentIdToken = context.getAuthorization().getToken(OidcIdToken.class).getToken();
                // Preserve the original authentication context; refreshing is not a new login.
                for (String claim : List.of("sid", IdTokenClaimNames.AUTH_TIME)) {
                    if (currentIdToken.hasClaim(claim)) {
                        claimsBuilder.claim(claim, currentIdToken.getClaim(claim));
                    }
                }
            }
        }

        JwtEncodingContext.Builder jwtContextBuilder = JwtEncodingContext.with(jwsHeaderBuilder, claimsBuilder)
                .registeredClient(registeredClient)
                .principal(context.getPrincipal())
                .authorizationServerContext(context.getAuthorizationServerContext())
                .authorizedScopes(context.getAuthorizedScopes())
                .tokenType(context.getTokenType())
                .authorizationGrantType(context.getAuthorizationGrantType())
                .authorizationGrant(context.getAuthorizationGrant());
        if (context.getAuthorization() != null) {
            jwtContextBuilder.authorization(context.getAuthorization());
        }
        if (context.hasKey(DPoPProof.class))
            jwtContextBuilder.put(DPoPProof.class, context.get(DPoPProof.class));
        if (!idToken && DPoPTokenBinding.confirmation(context) != null)
            claimsBuilder.claim(DPoPTokenBinding.CNF, DPoPTokenBinding.confirmation(context));
        this.jwtCustomizer.customize(jwtContextBuilder.build());

        JwsHeader jwsHeader = jwsHeaderBuilder.build();
        JwtClaimsSet claims = claimsBuilder.build();
        if (!idToken)
            DPoPTokenBinding.validateClaims(context, claims.getClaims());
        JwtClaimsBuilder smallRyeClaims = io.smallrye.jwt.build.Jwt.claims(claims.getClaims());
        JwtSignatureBuilder signature = smallRyeClaims.jws()
                .algorithm(io.smallrye.jwt.algorithm.SignatureAlgorithm.fromAlgorithm(jwsHeader.getAlgorithm()))
                .keyId(jwsHeader.getKeyId())
                .type(jwsHeader.getType());
        for (Map.Entry<String, Object> header : jwsHeader.getHeaders().entrySet()) {
            if (!Set.of("alg", "kid", "typ").contains(header.getKey())) {
                signature.header(header.getKey(), header.getValue());
            }
        }
        signingKey = this.keyManager.getSigningKey(jwsHeader.getKeyId(), jwsHeader.getAlgorithm());
        String tokenValue = signature.sign(signingKey.privateKey());
        return new Jwt(tokenValue, claims.getClaimAsInstant("iat"), claims.getClaimAsInstant("exp"),
                jwsHeader.getHeaders(), claims.getClaims());
    }
}

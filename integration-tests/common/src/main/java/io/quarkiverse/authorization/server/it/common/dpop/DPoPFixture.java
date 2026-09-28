package io.quarkiverse.authorization.server.it.common.dpop;

import java.time.Instant;
import java.util.*;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jose4j.jwk.PublicJsonWebKey;

import io.quarkiverse.authorization.server.authorization.OAuth2Authorization;
import io.quarkiverse.authorization.server.authorization.OAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.RegisteredClientRepository;
import io.quarkiverse.authorization.server.dpop.DPoPReplayStore;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofVerifier;
import io.quarkiverse.authorization.server.runtime.token.AuthorizationServerKeyManager;
import io.quarkiverse.authorization.server.settings.OAuth2TokenFormat;
import io.quarkiverse.authorization.server.token.OAuth2AccessToken;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.smallrye.common.annotation.Blocking;
import io.vertx.ext.web.RoutingContext;

/** Test-only seeded tokens: not an OAuth grant or a DPoP token-issuance implementation. */
@Path("/fixture")
@Singleton
@Blocking
@jakarta.ws.rs.Produces(MediaType.APPLICATION_JSON)
@UnlessBuildProfile("multiple-issuers")
public class DPoPFixture {
    @Inject
    AuthorizationServerKeyManager keys;
    @Inject
    OAuth2AuthorizationService authorizations;
    @Inject
    RegisteredClientRepository clients;
    @Inject
    DPoPProofVerifier verifier;
    @Inject
    DPoPReplayStore replay;
    @Inject
    RoutingContext routing;

    @ConfigProperty(name = "quarkus.authorization-server.issuer")
    String issuer;

    @POST
    @Path("/tokens")
    @Consumes(MediaType.APPLICATION_JSON)
    public Map<String, String> tokens(Map<String, Object> publicJwk) throws Exception {
        String jkt = PublicJsonWebKey.Factory.newPublicJwk(publicJwk)
                .calculateBase64urlEncodedThumbprint("SHA-256");
        Instant now = Instant.now();
        Instant expires = now.plusSeconds(300);
        Map<String, Object> claims = new LinkedHashMap<>(
                Map.of(
                        "iss",
                        issuer,
                        "sub",
                        "dpop-resource-server",
                        "username",
                        "dpop-resource-server",
                        "iat",
                        now.getEpochSecond(),
                        "exp",
                        expires.getEpochSecond(),
                        "scope",
                        "message.read",
                        "cnf",
                        Map.of("jkt", jkt)));
        String jwt = io.smallrye.jwt.build.Jwt.claims(claims)
                .jws()
                .keyId(keys.getKeyId())
                .sign(keys.getPrivateKey());
        String opaque = UUID.randomUUID().toString();
        // Persist the same temporal representation as the production token generators.
        Map<String, Object> persistedClaims = new LinkedHashMap<>(claims);
        persistedClaims.put("iat", now);
        persistedClaims.put("exp", expires);
        for (String token : List.of(jwt, opaque)) {
            var access = new OAuth2AccessToken(
                    new OAuth2AccessToken.TokenType("DPoP"),
                    token,
                    now,
                    expires,
                    Set.of("message.read"));
            authorizations.save(
                    OAuth2Authorization.withRegisteredClient(
                            clients.findByClientId("dpop-resource-server"))
                            .principalName("dpop-resource-server")
                            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                            .authorizedScopes(Set.of("message.read"))
                            .token(
                                    access,
                                    metadata -> {
                                        metadata.put(
                                                OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                                                persistedClaims);
                                        metadata.put(
                                                OAuth2TokenFormat.class.getName(),
                                                token.equals(jwt) ? "self-contained" : "reference");
                                    })
                            .build());
            // A seeded token must survive the same JDBC read used by Introspection and UserInfo.
            if (authorizations.findByToken(token, OAuth2TokenType.ACCESS_TOKEN) == null) {
                throw new IllegalStateException("Seeded token was not persisted");
            }
        }
        return Map.of("jwt", jwt, "opaque", opaque);
    }

    /** HTTP consumer of the new foundation; deliberately returns no OAuth tokens. */
    @POST
    @Path("/proof")
    public Response proof(@QueryParam("expected_jkt") String expectedJkt) {
        try {
            var request = DPoPProofRequest.from(routing);
            var verified = verifier.verify(request);
            if (expectedJkt != null && !expectedJkt.equals(verified.jwkThumbprint()))
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
            if (!replay.claim(new DPoPReplayStore.Key(request.uri(), verified.jwkThumbprint(), verified.jwtId()),
                    verified.expiresAt()))
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
            return Response.ok(Map.of("jkt", verified.jwkThumbprint())).build();
        } catch (OAuth2AuthenticationException e) {
            return Response.status(400)
                    .entity(Map.of("error", e.getError().getErrorCode()))
                    .build();
        }
    }
}

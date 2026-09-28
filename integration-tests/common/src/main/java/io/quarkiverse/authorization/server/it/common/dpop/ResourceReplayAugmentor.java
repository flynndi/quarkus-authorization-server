package io.quarkiverse.authorization.server.it.common.dpop;

import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;

import io.quarkiverse.authorization.server.dpop.DPoPReplayStore;
import io.quarkiverse.authorization.server.runtime.config.AuthorizationServerRuntimeConfig;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofRequest;
import io.quarkiverse.authorization.server.runtime.dpop.DPoPProofVerifier;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.*;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;

/** Test application integration: OIDC has already verified signature, URI, ath and cnf.jkt. */
@ApplicationScoped
@UnlessBuildProfile("multiple-issuers")
public class ResourceReplayAugmentor implements SecurityIdentityAugmentor {
    @Inject
    DPoPProofVerifier verifier;
    @Inject
    DPoPReplayStore replay;
    @Inject
    AuthorizationServerRuntimeConfig config;

    @Override
    public Uni<SecurityIdentity> augment(
            SecurityIdentity identity, AuthenticationRequestContext context) {
        return Uni.createFrom().item(identity);
    }

    @Override
    public Uni<SecurityIdentity> augment(
            SecurityIdentity identity,
            AuthenticationRequestContext context,
            Map<String, Object> attributes) {
        var routing = HttpSecurityUtils.getRoutingContextAttribute(attributes);
        // This exact resource path is routed exclusively to the guarded DPoP OIDC tenant.
        if (identity.isAnonymous()
                || routing == null
                || !routing.request().path().equals("/resource/guarded"))
            return Uni.createFrom().item(identity);
        return context.runBlocking(
                () -> {
                    try {
                        var request = DPoPProofRequest.from(routing);
                        if (request.proof().length() > config.dpop().maxProofLength())
                            throw new AuthenticationFailedException();
                        JsonWebSignature jwt = new JsonWebSignature();
                        jwt.setCompactSerialization(request.proof());
                        var publicJwk = jwt.getHeaders().getPublicJwkHeaderValue("jwk", null);
                        var claims = JsonUtil.parseJson(jwt.getUnverifiedPayload());
                        var proof = verifier.validateReplayClaims(
                                publicJwk.calculateBase64urlEncodedThumbprint("SHA-256"),
                                claims);
                        if (!replay.claim(
                                new DPoPReplayStore.Key(request.uri(), proof.jwkThumbprint(), proof.jwtId()),
                                proof.expiresAt()))
                            throw new AuthenticationFailedException();
                        return identity;
                    } catch (Exception e) {
                        throw new AuthenticationFailedException();
                    }
                });
    }
}

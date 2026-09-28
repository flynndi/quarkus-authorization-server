package io.quarkiverse.authorization.server.it.multipleissuers;

import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;

import io.quarkus.arc.profile.IfBuildProfile;
import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;

/** quarkus-oidc selects the resource tenant and checks its issuer and signing key. */
@Path("/{tenant}/message")
@IfBuildProfile("multiple-issuers")
public class MessageResource {
    @Inject
    SecurityIdentity identity;

    @GET
    @Authenticated
    public Map<String, String> message(@PathParam("tenant") String tenant) {
        return Map.of("tenant", tenant, "subject", this.identity.getPrincipal().getName());
    }
}

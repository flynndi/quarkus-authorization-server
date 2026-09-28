package io.quarkiverse.authorization.server.it.common.dpop;

import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;

import io.quarkus.arc.profile.UnlessBuildProfile;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.identity.SecurityIdentity;

@Path("/resource")
@Produces(MediaType.APPLICATION_JSON)
@UnlessBuildProfile("multiple-issuers")
public class Resource {
    @Inject
    SecurityIdentity identity;
    @Inject
    AccessTokenCredential accessToken;

    @GET
    @Path("/{mode}")
    @PermissionsAllowed("message.read")
    public Map<String, Object> get() {
        return Map.of(
                "subject", identity.getPrincipal().getName(), "opaque", accessToken.isOpaque());
    }
}

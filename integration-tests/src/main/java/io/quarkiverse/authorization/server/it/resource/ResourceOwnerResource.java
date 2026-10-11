package io.quarkiverse.authorization.server.it.resource;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.common.annotation.RunOnVirtualThread;

@Path("/api/resource")
@Produces(MediaType.APPLICATION_JSON)
@RunOnVirtualThread
public class ResourceOwnerResource {

    @Inject
    SecurityIdentity securityIdentity;

    @Inject
    JsonWebToken jsonWebToken;

    @GET
    @Path("/securityIdentity")
    @PermissionsAllowed("securityIdentity")
    public Response getSecurityIdentity() {
        return Response.ok(securityIdentity.getPrincipal()).build();
    }

    @GET
    @Path("/jsonWebToken")
    @PermissionsAllowed("jsonWebToken")
    public Response getJsonWebToken() {
        return Response.ok(jsonWebToken).build();
    }
}

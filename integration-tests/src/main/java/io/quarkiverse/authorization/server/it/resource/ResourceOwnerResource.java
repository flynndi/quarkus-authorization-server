package io.quarkiverse.authorization.server.it.resource;

import java.util.Set;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

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
    public IdentityView getSecurityIdentity() {
        return new IdentityView(securityIdentity.getPrincipal().getName(), securityIdentity.getRoles());
    }

    @GET
    @Path("/jsonWebToken")
    @PermissionsAllowed("jsonWebToken")
    public TokenView getJsonWebToken() {
        return new TokenView(jsonWebToken.getSubject(), jsonWebToken.getIssuer(), jsonWebToken.getGroups());
    }

    public record IdentityView(String name, Set<String> roles) {
    }

    public record TokenView(String subject, String issuer, Set<String> groups) {
    }
}

package io.quarkiverse.authorization.server.example.authorizationcode.resourceserver;

import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.identity.SecurityIdentity;

/** The resource server shares this process but accepts only OAuth bearer credentials. */
@Path("/api/messages")
@Produces(MediaType.APPLICATION_JSON)
public final class MessageResource {
    @Inject
    SecurityIdentity identity;

    @GET
    @PermissionsAllowed("message.read")
    public Map<String, Object> messages() {
        return Map.of("subject", this.identity.getPrincipal().getName(), "message", "Hello from the protected Quarkus API");
    }
}

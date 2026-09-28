package org.acme;

import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.identity.SecurityIdentity;

@Path("/api/messages")
@Produces(MediaType.APPLICATION_JSON)
public class MessageResource {
    @Inject
    SecurityIdentity identity;

    @GET
    @PermissionsAllowed("message.read")
    public Map<String, String> messages() {
        return Map.of("subject", this.identity.getPrincipal().getName(), "message", "Hello, OAuth!");
    }
}

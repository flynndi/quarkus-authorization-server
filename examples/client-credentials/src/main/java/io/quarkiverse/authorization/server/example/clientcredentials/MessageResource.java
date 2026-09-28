package io.quarkiverse.authorization.server.example.clientcredentials;

import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.security.PermissionsAllowed;

/** The OIDC extension verifies the bearer JWT and turns its scopes into permissions. */
@Path("/api/messages")
public class MessageResource {

    @Inject
    JsonWebToken accessToken;

    @GET
    @PermissionsAllowed("message.read")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> messages() {
        return Map.of("subject", this.accessToken.getSubject(),
                "issuer", this.accessToken.getIssuer(),
                "audience", this.accessToken.getAudience(),
                "expires_at", this.accessToken.getExpirationTime());
    }
}

package io.quarkiverse.authorization.server.example.resource;

import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.security.Authenticated;

@Path("/api/resource")
@Authenticated
public class ResourceServerResource {

    @Inject
    JsonWebToken accessToken;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> get() {
        return Map.of(
                "subject", this.accessToken.getSubject(),
                "issuer", this.accessToken.getIssuer(),
                "audience", this.accessToken.getAudience());
    }
}

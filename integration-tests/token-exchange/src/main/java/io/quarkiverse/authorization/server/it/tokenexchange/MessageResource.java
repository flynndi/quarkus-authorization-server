package io.quarkiverse.authorization.server.it.tokenexchange;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.identity.SecurityIdentity;

/** Resource-server boundary that exposes claims only after Quarkus OIDC verification. */
@Path("/api/messages")
public class MessageResource {

    @Inject
    JsonWebToken accessToken;

    @Inject
    AccessTokenCredential credential;

    @Inject
    SecurityIdentity identity;

    @GET
    @PermissionsAllowed("message.read")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> messages() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("subject", this.identity.getPrincipal().getName());
        result.put("format", this.credential.isOpaque() ? "reference" : "self-contained");
        if (!this.credential.isOpaque()) {
            result.put("audience", this.accessToken.getAudience());
            Object act = this.accessToken.getClaim("act");
            if (act instanceof JsonObject actClaim) {
                result.put("act", plainActClaim(actClaim));
            }
        }
        return result;
    }

    private static Map<String, Object> plainActClaim(JsonObject actClaim) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("sub", actClaim.getString("sub"));
        JsonObject previous = actClaim.getJsonObject("act");
        if (previous != null) {
            result.put("act", plainActClaim(previous));
        }
        return result;
    }
}

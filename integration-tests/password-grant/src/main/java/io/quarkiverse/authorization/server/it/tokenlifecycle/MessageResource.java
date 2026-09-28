package io.quarkiverse.authorization.server.it.tokenlifecycle;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.oidc.TokenIntrospection;
import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.identity.SecurityIdentity;

/** Resource-server boundary: opaque state is accepted only through Quarkus OIDC introspection. */
@Path("/lifecycle/messages")
public class MessageResource {

    @Inject
    SecurityIdentity identity;

    @Inject
    AccessTokenCredential accessToken;

    @Inject
    TokenIntrospection introspection;

    @GET
    @PermissionsAllowed("message.read")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> messages() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("subject", this.identity.getPrincipal().getName());
        result.put("format", this.accessToken.isOpaque() ? "reference" : "self-contained");
        if (this.accessToken.isOpaque()) {
            result.put("introspection_active", this.introspection.isActive());
            result.put("introspection_client_id", this.introspection.getClientId());
            result.put("introspection_scopes", this.introspection.getScopes());
        }
        return result;
    }
}

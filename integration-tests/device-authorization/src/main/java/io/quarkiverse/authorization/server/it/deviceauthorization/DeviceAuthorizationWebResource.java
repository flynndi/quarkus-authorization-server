package io.quarkiverse.authorization.server.it.deviceauthorization;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

import io.quarkus.qute.TemplateInstance;

@Path("/")
@Produces(MediaType.TEXT_HTML)
public final class DeviceAuthorizationWebResource {

    @GET
    public TemplateInstance index() {
        return DeviceAuthorizationTemplates.index();
    }

    @GET
    @Path("login")
    public TemplateInstance login(@QueryParam("error") String error) {
        return DeviceAuthorizationTemplates.login(error != null);
    }
}

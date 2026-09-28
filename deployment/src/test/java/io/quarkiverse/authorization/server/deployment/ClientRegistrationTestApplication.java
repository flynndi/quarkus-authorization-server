package io.quarkiverse.authorization.server.deployment;

import java.util.Arrays;

import jakarta.inject.Singleton;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/** Isolated Quarkus application fixture; initial tokens are provisioned by tests, never an HTTP bootstrap endpoint. */
public final class ClientRegistrationTestApplication {
    static JavaArchive application(JavaArchive jar) {
        return baseApplication(jar).addClass(RegistrationScopePolicy.class);
    }

    static JavaArchive baseApplication(JavaArchive jar) {
        return jar
                .addClasses(ClientRegistrationTestApplication.class, ResourceOwner.class, OtherResource.class,
                        ClientAssertionTestSupport.class)
                .addAsResource("privateKey.pem").addAsResource("publicKey.pem")
                .addAsResource(new StringAsset("""
                        quarkus.http.root-path=/api
                        quarkus.http.auth.basic=true
                        quarkus.http.auth.proactive=false
                        quarkus.authorization-server.issuer=https://issuer.example/api
                        quarkus.authorization-server.oidc.enabled=true
                        quarkus.authorization-server.oidc.client-registration.enabled=true
                        quarkus.authorization-server.oidc-client-registration-endpoint=/clients
                        quarkus.authorization-server.signing.key-id=registration-test-key
                        quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                        quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                        quarkus.authorization-server.clients.bootstrap.authorization-grant-types=client_credentials
                        """), "application.properties");
    }

    @Singleton
    public static class ResourceOwner implements IdentityProvider<UsernamePasswordAuthenticationRequest> {
        @Override
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            if (!"owner".equals(request.getUsername())
                    || !Arrays.equals("password".toCharArray(), request.getPassword().getPassword())) {
                return Uni.createFrom().failure(new AuthenticationFailedException());
            }
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal("owner")).build());
        }
    }

    @Path("/other")
    public static class OtherResource {
        @GET
        public String get() {
            return "unaffected";
        }
    }
}

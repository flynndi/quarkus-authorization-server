package io.quarkiverse.authorization.server.deployment;

import java.util.Arrays;
import java.util.Map;

import jakarta.inject.Singleton;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;

import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

/** Shared application archive, separate from QuarkusUnitTest's isolated test classes. */
public final class UserInfoTestApplication {
    static JavaArchive application(JavaArchive jar) {
        return jar
                .addClasses(UserInfoTestApplication.class, ResourceOwnerIdentityProvider.class, ProfileClaims.class,
                        OtherResource.class)
                .addAsResource("privateKey.pem").addAsResource("publicKey.pem")
                .addAsResource(
                        new StringAsset(
                                """
                                        quarkus.http.root-path=/api
                                        quarkus.http.auth.basic=true
                                        quarkus.authorization-server.issuer=https://issuer.example/api
                                        quarkus.authorization-server.oidc.enabled=true
                                        quarkus.authorization-server.oidc-user-info-endpoint=/me
                                        quarkus.authorization-server.signing.key-id=test-key
                                        quarkus.authorization-server.signing.private-key-location=classpath:privateKey.pem
                                        quarkus.authorization-server.signing.public-key-location=classpath:publicKey.pem
                                        quarkus.authorization-server.clients.client.client-secret=$2a$10$3bgssgqbOgnoJMXLtqLvx.vYFvvDpzVJuBZqtIp7qhbV0YjUxdQXK
                                        quarkus.authorization-server.clients.client.authorization-grant-types=password,refresh_token
                                        quarkus.authorization-server.clients.client.scopes=openid,profile,email,address,phone,message.read
                                        quarkus.authorization-server.clients.client.reuse-refresh-tokens=false
                                        """),
                        "application.properties");
    }

    @Singleton
    public static class ResourceOwnerIdentityProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {
        @Override
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            if (!"resource-owner".equals(request.getUsername()) ||
                    !Arrays.equals("resource-owner-password".toCharArray(), request.getPassword().getPassword())) {
                return Uni.createFrom().failure(new AuthenticationFailedException());
            }
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal(request.getUsername())).build());
        }
    }

    @Singleton
    public static class ProfileClaims implements OAuth2TokenCustomizer<JwtEncodingContext> {
        @Override
        public void customize(JwtEncodingContext context) {
            if ("id_token".equals(context.getTokenType().getValue())) {
                context.getClaims().claim("name", "Resource Owner").claim("email", "owner@example.com")
                        .claim("email_verified", true).claim("address", Map.of("country", "CN"))
                        .claim("phone_number", "+123").claim("private_claim", "must-not-leak");
            }
        }
    }

    @Path("/elsewhere")
    public static class OtherResource {
        @GET
        public String get() {
            return "unaffected";
        }
    }
}

package io.quarkiverse.authorization.server.it.multipleissuers;

import jakarta.inject.Singleton;

import io.quarkus.arc.profile.IfBuildProfile;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

@IfBuildProfile("multiple-issuers")

public final class DemoUsers {
    @Singleton
    @IfBuildProfile("multiple-issuers")
    public static class PasswordProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            return "alice".equals(request.getUsername())
                    && java.util.Arrays.equals("password".toCharArray(), request.getPassword().getPassword())
                            ? Uni.createFrom().item(identity(request.getUsername()))
                            : Uni.createFrom().failure(new AuthenticationFailedException());
        }
    }

    @Singleton
    @IfBuildProfile("multiple-issuers")
    public static class TrustedProvider implements IdentityProvider<TrustedAuthenticationRequest> {
        public Class<TrustedAuthenticationRequest> getRequestType() {
            return TrustedAuthenticationRequest.class;
        }

        public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest request, AuthenticationRequestContext context) {
            return "alice".equals(request.getPrincipal()) ? Uni.createFrom().item(identity(request.getPrincipal()))
                    : Uni.createFrom().failure(new AuthenticationFailedException());
        }
    }

    private static SecurityIdentity identity(String name) {
        return QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(name)).build();
    }
}

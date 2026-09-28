package io.quarkiverse.authorization.server.deployment;

import jakarta.inject.Singleton;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

public final class LogoutTestApplication {
    @Singleton
    public static class PasswordProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                AuthenticationRequestContext context) {
            return java.util.Arrays.equals("password".toCharArray(), request.getPassword().getPassword())
                    ? Uni.createFrom().item(identity(request.getUsername()))
                    : Uni.createFrom().failure(new AuthenticationFailedException());
        }
    }

    @Singleton
    public static class TrustedProvider implements IdentityProvider<TrustedAuthenticationRequest> {
        public Class<TrustedAuthenticationRequest> getRequestType() {
            return TrustedAuthenticationRequest.class;
        }

        public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest request, AuthenticationRequestContext context) {
            return Uni.createFrom().item(identity(request.getPrincipal()));
        }
    }

    private static SecurityIdentity identity(String name) {
        return QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(name)).build();
    }
}

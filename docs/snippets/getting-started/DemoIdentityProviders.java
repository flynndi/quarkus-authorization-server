package org.acme;

import java.util.Map;
import java.util.Set;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

@Singleton
public class DemoIdentityProviders {
    // This application owns its users. Replace the map with your user service.
    private final Map<String, User> users = Map.of(
            "alice", new User("alice", BcryptUtil.bcryptHash("alice-password"),
                    Set.of("user"), Set.of("message.read")));

    @Produces
    @Singleton
    public IdentityProvider<UsernamePasswordAuthenticationRequest> passwordIdentityProvider() {
        return new IdentityProvider<>() {
            @Override
            public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
                return UsernamePasswordAuthenticationRequest.class;
            }

            @Override
            public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                return context.runBlocking(() -> {
                    User user = findUser(request.getUsername());
                    if (!BcryptUtil.matches(new String(request.getPassword().getPassword()), user.passwordHash())) {
                        throw new AuthenticationFailedException();
                    }
                    return identity(user);
                });
            }
        };
    }

    @Produces
    @Singleton
    public IdentityProvider<TrustedAuthenticationRequest> trustedIdentityProvider() {
        return new IdentityProvider<>() {
            @Override
            public Class<TrustedAuthenticationRequest> getRequestType() {
                return TrustedAuthenticationRequest.class;
            }

            @Override
            public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                // Quarkus Form has validated the cookie; reload the application's user.
                return context.runBlocking(() -> identity(findUser(request.getPrincipal())));
            }
        };
    }

    private User findUser(String username) {
        User user = this.users.get(username);
        if (user == null) {
            throw new AuthenticationFailedException();
        }
        return user;
    }

    private static SecurityIdentity identity(User user) {
        return QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(user.username()))
                .addRoles(user.roles())
                .addPermissionsAsString(user.permissions())
                .build();
    }

    private record User(String username, String passwordHash, Set<String> roles, Set<String> permissions) {
    }
}

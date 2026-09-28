package io.quarkiverse.authorization.server.example.authorizationcode.authorizationserver.config;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.example.authorizationcode.authorizationserver.service.UserService;
import io.quarkiverse.authorization.server.example.authorizationcode.authorizationserver.user.User;
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

/** Adapts application-owned users to Quarkus password authentication and Form cookie restoration. */
@Singleton
public class ResourceOwnerIdentityProviders {

    private final UserService userService;

    public ResourceOwnerIdentityProviders(UserService userService) {
        this.userService = userService;
    }

    @Produces
    @Singleton
    public IdentityProvider<UsernamePasswordAuthenticationRequest> resourceOwnerIdentityProvider() {
        return new IdentityProvider<>() {
            @Override
            public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
                return UsernamePasswordAuthenticationRequest.class;
            }

            @Override
            public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                // Password hashing is CPU intensive; use Quarkus's authentication worker context.
                return context.runBlocking(() -> {
                    User user = userService.findUser(request.getUsername());
                    if (!BcryptUtil.matches(new String(request.getPassword().getPassword()), user.passwordHash())) {
                        throw new AuthenticationFailedException();
                    }
                    return QuarkusSecurityIdentity.builder()
                            .setPrincipal(new QuarkusPrincipal(user.username()))
                            .addRoles(user.roles())
                            .addPermissionsAsString(user.permissions())
                            .build();
                });
            }
        };
    }

    @Produces
    @Singleton
    public IdentityProvider<TrustedAuthenticationRequest> trustedResourceOwnerIdentityProvider() {
        return new IdentityProvider<>() {
            @Override
            public Class<TrustedAuthenticationRequest> getRequestType() {
                return TrustedAuthenticationRequest.class;
            }

            @Override
            public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest request,
                    AuthenticationRequestContext context) {
                // Quarkus has already validated the encrypted Form cookie. Reload the current user.
                return Uni.createFrom().item(() -> {
                    User user = userService.findUser(request.getPrincipal());
                    return QuarkusSecurityIdentity.builder()
                            .setPrincipal(new QuarkusPrincipal(user.username()))
                            .addRoles(user.roles())
                            .addPermissionsAsString(user.permissions())
                            .build();
                });
            }
        };
    }
}

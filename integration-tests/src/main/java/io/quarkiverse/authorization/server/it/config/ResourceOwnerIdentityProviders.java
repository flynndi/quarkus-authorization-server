package io.quarkiverse.authorization.server.it.config;

import java.util.Objects;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.it.repository.UserRepository;
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

    private final UserRepository userRepository;

    public ResourceOwnerIdentityProviders(UserRepository userRepository) {
        this.userRepository = userRepository;
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
                return context.runBlocking(() -> {
                    UserRepository.UserRoleResult result = userRepository.findByUsername(request.getUsername());
                    if (Objects.isNull(result) || !result.enabled()
                            || !BcryptUtil.matches(new String(request.getPassword().getPassword()), result.password())) {
                        throw new AuthenticationFailedException();
                    }
                    return ResourceOwnerIdentityProviders.createIdentity(result);
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
                return context.runBlocking(() -> {
                    UserRepository.UserRoleResult result = userRepository.findByUsername(request.getPrincipal());
                    if (Objects.isNull(result) || !result.enabled()) {
                        throw new AuthenticationFailedException();
                    }
                    return ResourceOwnerIdentityProviders.createIdentity(result);
                });
            }
        };
    }

    private static SecurityIdentity createIdentity(UserRepository.UserRoleResult user) {
        var builder = QuarkusSecurityIdentity.builder()
                .setPrincipal(new QuarkusPrincipal(user.username()));
        for (var role : user.rolePermissionResults()) {
            builder.addRole(role.code());
            for (var permission : role.permissions()) {
                builder.addPermissionAsString(permission.getCode());
            }
        }
        return builder.build();
    }
}

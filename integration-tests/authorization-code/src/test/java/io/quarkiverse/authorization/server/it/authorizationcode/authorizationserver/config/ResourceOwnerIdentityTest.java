package io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.config;

import java.util.List;
import java.util.Set;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.it.authorizationcode.authorizationserver.service.UserService;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.StringPermission;
import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
class ResourceOwnerIdentityTest {

    @Inject
    IdentityProviderManager identities;

    @Test
    void passwordAndCookieRestorationUseTheSameUserPermissionsWithoutRetainingThePassword() {
        SecurityIdentity password = this.identities.authenticateBlocking(new UsernamePasswordAuthenticationRequest(
                UserService.RESOURCE_OWNER,
                new PasswordCredential(UserService.RESOURCE_OWNER_PASSWORD.toCharArray())));
        SecurityIdentity restored = this.identities.authenticateBlocking(
                new TrustedAuthenticationRequest(UserService.RESOURCE_OWNER));

        for (SecurityIdentity identity : List.of(password, restored)) {
            Assertions.assertEquals(UserService.RESOURCE_OWNER, identity.getPrincipal().getName());
            Assertions.assertEquals(Set.of("user"), identity.getRoles());
            Assertions.assertTrue(identity.checkPermissionBlocking(new StringPermission("message.read")));
            Assertions.assertFalse(identity.checkPermissionBlocking(new StringPermission("message.write")));
            Assertions.assertTrue(identity.getCredentials().isEmpty());
            Assertions.assertTrue(identity.getAttributes().isEmpty());
        }
    }

    @Test
    void cookieRestorationRejectsAnUnknownUser() {
        Assertions.assertThrows(AuthenticationFailedException.class, () -> this.identities.authenticateBlocking(
                new TrustedAuthenticationRequest("unknown-user")));
    }
}

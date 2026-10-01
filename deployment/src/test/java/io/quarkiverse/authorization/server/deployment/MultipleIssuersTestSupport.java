package io.quarkiverse.authorization.server.deployment;

import java.util.List;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;

import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import io.quarkiverse.authorization.server.authorization.InMemoryOAuth2AuthorizationService;
import io.quarkiverse.authorization.server.client.InMemoryRegisteredClientRepository;
import io.quarkiverse.authorization.server.client.RegisteredClient;
import io.quarkiverse.authorization.server.jose.jws.SignatureAlgorithm;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.settings.ClientSettings;
import io.quarkiverse.authorization.server.tenant.AuthorizationServerTenant;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.smallrye.common.annotation.Identifier;
import io.smallrye.jwt.util.KeyUtils;

final class MultipleIssuersTestSupport {
    static JavaArchive application(JavaArchive jar, boolean proactive) {
        return jar
                .addClasses(ClientAssertionTestSupport.class, MultipleIssuersTestSupport.class, Tenants.class,
                        LogoutTestApplication.class, LogoutTestApplication.PasswordProvider.class,
                        LogoutTestApplication.TrustedProvider.class)
                .addAsResource(new StringAsset("""
                        quarkus.http.root-path=/server
                        quarkus.http.auth.proactive=%s
                        quarkus.http.auth.session.encryption-key=multiple-issuers-form-test-key
                        quarkus.http.auth.form.enabled=true
                        quarkus.http.auth.form.login-page=/server/auth/login
                        quarkus.http.auth.form.error-page=/server/auth/login?error=true
                        quarkus.authorization-server.default-login-page-enabled=true
                        quarkus.authorization-server.multiple-issuers-allowed=true
                        quarkus.authorization-server.issuers.alpha=https://server.example/server/alpha
                        quarkus.authorization-server.issuers.beta=https://server.example/server/beta
                        quarkus.authorization-server.oidc.enabled=true
                        quarkus.authorization-server.oidc.client-registration.enabled=true
                        quarkus.authorization-server.client-registration.enabled=true
                        quarkus.authorization-server.pushed-authorization-requests-enabled=true
                        quarkus.authorization-server.authorization-endpoint=/authorize
                        quarkus.authorization-server.token-endpoint=/token
                        """.formatted(proactive)), "application.properties");
    }

    @Singleton
    public static class Tenants {
        @Produces
        @Singleton
        @Identifier("alpha")
        AuthorizationServerTenant alpha() throws Exception {
            return Tenants.tenant("alpha");
        }

        @Produces
        @Singleton
        @Identifier("beta")
        AuthorizationServerTenant beta() throws Exception {
            return Tenants.tenant("beta");
        }

        private static AuthorizationServerTenant tenant(String name) throws Exception {
            var clients = new InMemoryRegisteredClientRepository(RegisteredClient.withId("same-id").clientId("shared")
                    .clientSecret(BcryptUtil.bcryptHash(name + "-secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                    .redirectUri("https://client.example/callback").postLogoutRedirectUri("https://client.example/logout")
                    .scope("openid").scope("profile").scope(name)
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build());
            clients.save(RegisteredClient.withId("assertion-id").clientId("assertion")
                    .clientSecret("0123456789abcdef0123456789abcdef")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope(name)
                    .clientSettings(ClientSettings.builder().tokenEndpointAuthenticationSigningAlgorithm(
                            io.quarkiverse.authorization.server.jose.jws.MacAlgorithm.HS256).build())
                    .build());
            var pair = KeyUtils.generateKeyPair(2048);
            return new AuthorizationServerTenant(clients, new InMemoryOAuth2AuthorizationService(),
                    new InMemoryOAuth2AuthorizationConsentService(),
                    () -> new AuthorizationServerKeySource.KeySet(List.of(new AuthorizationServerKeySource.Key(name,
                            SignatureAlgorithm.RS256, pair.getPrivate(), pair.getPublic())), name));
        }
    }
}

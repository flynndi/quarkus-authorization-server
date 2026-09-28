package io.quarkiverse.authorization.server.deployment;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;

/** Shared Form fixture for proactive and lazy authentication; no extra application endpoint is needed. */
public final class AuthorizationInteractionTestSupport {
    private AuthorizationInteractionTestSupport() {
    }

    static JavaArchive application(JavaArchive jar, boolean proactive) {
        return jar.addClasses(LogoutTestApplication.class, LogoutTestApplication.PasswordProvider.class,
                LogoutTestApplication.TrustedProvider.class)
                .addAsResource(new StringAsset("""
                        quarkus.http.root-path=/server
                        quarkus.http.auth.proactive=%s
                        quarkus.http.auth.session.encryption-key=authorization-interaction-test-key
                        quarkus.http.auth.form.enabled=true
                        quarkus.http.auth.form.login-page=/server/auth/login
                        quarkus.http.auth.form.error-page=/server/auth/login?error=true
                        quarkus.authorization-server.default-login-page-enabled=true
                        quarkus.authorization-server.issuer=https://issuer.example/server
                        quarkus.authorization-server.oidc.enabled=true
                        quarkus.authorization-server.authorization-endpoint=/authorize
                        quarkus.authorization-server.clients.browser.client-authentication-methods=none
                        quarkus.authorization-server.clients.browser.authorization-grant-types=authorization_code
                        quarkus.authorization-server.clients.browser.redirect-uris=https://client.example/callback?tenant=a
                        quarkus.authorization-server.clients.browser.scopes=openid,message.read,message.write
                        quarkus.authorization-server.clients.browser.require-proof-key=true
                        quarkus.authorization-server.clients.browser.require-authorization-consent=true
                        quarkus.authorization-server.clients.direct.client-authentication-methods=none
                        quarkus.authorization-server.clients.direct.authorization-grant-types=authorization_code
                        quarkus.authorization-server.clients.direct.redirect-uris=https://client.example/callback?tenant=a
                        quarkus.authorization-server.clients.direct.scopes=openid,message.read
                        quarkus.authorization-server.clients.direct.require-proof-key=true
                        quarkus.authorization-server.clients.direct.require-authorization-consent=false
                        quarkus.authorization-server.clients.wrong-grant.authorization-grant-types=client_credentials
                        quarkus.authorization-server.clients.wrong-grant.redirect-uris=https://client.example/callback?tenant=a
                        quarkus.authorization-server.clients.wrong-grant.scopes=openid,message.read
                        """.formatted(proactive)), "application.properties");
    }
}

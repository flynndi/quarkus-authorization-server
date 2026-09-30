package io.quarkiverse.authorization.server.runtime.oidc.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import io.quarkiverse.authorization.server.oidc.session.OidcSessionManager;
import io.quarkiverse.authorization.server.oidc.session.SessionInformation;
import io.quarkiverse.authorization.server.runtime.context.CurrentAuthorizationServerContext;
import io.quarkiverse.authorization.server.settings.AuthorizationServerSettings;
import io.quarkus.arc.DefaultBean;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.runtime.VertxHttpConfig;
import io.quarkus.vertx.http.runtime.security.FormAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.PersistentLoginManager;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.vertx.core.http.Cookie;
import io.vertx.ext.web.RoutingContext;

/**
 * Complements Quarkus' stateless Form credential with encrypted OIDC login metadata.
 * This cookie cannot authenticate a request. Quarkus must first authenticate the Form credential.
 * Like Form Authentication itself, logout clears browser cookies; it is not server-side revocation.
 */
@Singleton
@DefaultBean
public final class FormAuthenticationSessionManager implements OidcSessionManager {
    private final PersistentLoginManager loginManager;
    private final String formCookieName;
    private final String cookieName;
    private final String cookiePath;
    private final String cookieDomain;
    private final SecureRandom random = new SecureRandom();

    @Inject
    public FormAuthenticationSessionManager(VertxHttpConfig config) {
        FormAuthConfig form = config.auth().form();
        this.formCookieName = form.cookieName();
        this.cookieName = this.formCookieName + ".oidc";
        this.cookiePath = form.cookiePath().orElse("/");
        this.cookieDomain = form.cookieDomain().orElse(null);
        // Domain separation prevents swapping Form and OIDC cookies, even with a shared configured key.
        String key = config.encryptionKey().map(value -> hash("oidc-session:" + value)).orElse(null);
        this.loginManager = new PersistentLoginManager(key, this.cookieName, form.timeout().toMillis(),
                form.newCookieInterval().toMillis(), true, form.cookieSameSite().name(), this.cookiePath,
                form.cookieMaxAge().map(java.time.Duration::toSeconds).orElse(-1L), this.cookieDomain);
    }

    void login(RoutingContext context, SecurityIdentity principal) {
        byte[] id = new byte[32];
        this.random.nextBytes(id);
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(id) + ":"
                + Instant.now().getEpochSecond() + ":"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(
                        principal.getPrincipal().getName().getBytes(StandardCharsets.UTF_8));
        this.loginManager.save(payload, context, this.cookieName, null, context.request().isSSL());
    }

    @Override
    public SessionInformation getSessionInformation(RoutingContext context, SecurityIdentity principal) {
        if (principal.isAnonymous()
                || !(context.get(HttpAuthenticationMechanism.class.getName()) instanceof FormAuthenticationMechanism)) {
            return null;
        }
        PersistentLoginManager.RestoreResult restored = this.loginManager.restore(context);
        if (restored == null) {
            // An old/untracked Form login is not a new authentication. Never fabricate auth_time here.
            return null;
        }
        String[] fields = restored.getPrincipal().split(":", 3);
        if (fields.length != 3) {
            return null;
        }
        try {
            String principalName = new String(Base64.getUrlDecoder().decode(fields[2]), StandardCharsets.UTF_8);
            if (!principalName.equals(principal.getPrincipal().getName())) {
                return null;
            }
            var issuerSettings = (AuthorizationServerSettings) context.get(CurrentAuthorizationServerContext.ATTRIBUTE);
            String sessionId = issuerSettings == null ? fields[0] : issuerSettings.getIssuer() + ":" + fields[0];
            SessionInformation session = new SessionInformation(principalName, hash(sessionId),
                    Instant.ofEpochSecond(Long.parseLong(fields[1])));
            this.loginManager.save(restored.getPrincipal(), context, this.cookieName, restored, context.request().isSSL());
            return session;
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    @Override
    public void logout(RoutingContext context, SecurityIdentity principal) {
        if (context.get(HttpAuthenticationMechanism.class.getName()) instanceof FormAuthenticationMechanism) {
            this.expireCookie(context, this.formCookieName);
            this.expireCookie(context, this.cookieName);
            QuarkusHttpUser.setIdentity(QuarkusSecurityIdentity.builder().setAnonymous(true).build(), context);
        }
    }

    private void expireCookie(RoutingContext context, String name) {
        // Quarkus Form logout omits Domain. Match the issuance tuple so Vert.x also replaces
        // any renewal queued by Form authentication or getSessionInformation on this request.
        Cookie cookie = Cookie.cookie(name, "").setPath(this.cookiePath)
                .setMaxAge(0).setHttpOnly(true).setSecure(context.request().isSSL());
        if (this.cookieDomain != null) {
            cookie.setDomain(this.cookieDomain);
        }
        context.response().addCookie(cookie);
    }

    private static String hash(String value) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}

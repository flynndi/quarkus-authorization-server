package io.quarkiverse.authorization.server.runtime.grant.authorizationcode.web;

import java.net.URI;
import java.util.List;
import java.util.Map;

import jakarta.inject.Inject;

import io.netty.handler.codec.http.QueryStringDecoder;
import io.quarkiverse.authorization.server.runtime.web.DefaultBrowserPage;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.runtime.VertxHttpConfig;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/** HTML only: Quarkus Form authenticates the POST, maintains its cookie and restores the request. */
public final class DefaultLoginPage implements Handler<RoutingContext> {

    private final String loginPath;
    private final String errorPath;
    private final Map<String, List<String>> errorQuery;
    private final String postPath;
    private final String form;

    @Inject
    public DefaultLoginPage(VertxHttpConfig config) {
        this(config.auth().form());
    }

    public DefaultLoginPage(FormAuthConfig config) {
        URI login = DefaultLoginPage.pageUri(config.loginPage().orElseThrow(
                () -> new ConfigurationException("The default login page requires quarkus.http.auth.form.login-page")),
                "login-page");
        URI error = config.errorPage().map(value -> DefaultLoginPage.pageUri(value, "error-page")).orElse(null);
        URI post = DefaultLoginPage.pageUri(config.postLocation(), "post-location");
        this.postPath = post.getPath();
        this.loginPath = login.getPath();
        this.errorPath = error == null ? null : error.getPath();
        this.errorQuery = error == null ? Map.of() : new QueryStringDecoder(error.toString()).parameters();
        if (this.loginPath.equals(this.errorPath) && this.errorQuery.isEmpty()) {
            throw new ConfigurationException("The default login page requires a distinct form.error-page path "
                    + "or an error query parameter, for example /login.html?error=true");
        }
        if (post.getRawQuery() != null) {
            throw new ConfigurationException("quarkus.http.auth.form.post-location must be a path "
                    + "without a query when the default login page is enabled");
        }
        this.form = """
                <form method="post" action="%s">
                <div class="field"><label for="username">Username</label>
                <input id="username" type="text" name="%s" autocomplete="username" required autofocus></div>
                <div class="field"><label for="password">Password</label>
                <input id="password" type="password" name="%s" autocomplete="current-password" required></div>
                <button type="submit">Sign in</button>
                </form>
                """.formatted(DefaultBrowserPage.escapeHtml(post.toString()),
                DefaultBrowserPage.escapeHtml(config.usernameParameter()),
                DefaultBrowserPage.escapeHtml(config.passwordParameter()));
    }

    String[] paths() {
        return this.errorPath == null || this.loginPath.equals(this.errorPath)
                ? new String[] { this.loginPath }
                : new String[] { this.loginPath, this.errorPath };
    }

    String postPath() {
        return this.postPath;
    }

    @Override
    public void handle(RoutingContext context) {
        String path = context.normalizedPath();
        if (!this.loginPath.equals(path) && !path.equals(this.errorPath)) {
            context.next();
            return;
        }
        boolean failed = path.equals(this.errorPath) && this.errorQuery.entrySet().stream()
                .allMatch(entry -> context.queryParam(entry.getKey()).equals(entry.getValue()));
        String body = "<p class=\"lead\">Use your account to continue.</p>"
                + (failed ? "<p class=\"error\" role=\"alert\">Invalid username or password. Please try again.</p>" : "")
                + this.form;
        DefaultBrowserPage.write(context, "Sign in", body);
    }

    private static URI pageUri(String value, String property) {
        try {
            // Match FormAuthenticationMechanism's server-absolute page locations, including
            // its support for values without a leading slash. Never infer the HTTP root path.
            URI uri = URI.create(value.startsWith("/") ? value : "/" + value);
            if (uri.getAuthority() != null || uri.getFragment() != null
                    || uri.getPath() == null || !uri.normalize().equals(uri)
                    || value.contains(":") || value.contains("\\") || value.contains("*")) {
                throw new IllegalArgumentException();
            }
            return uri;
        } catch (IllegalArgumentException exception) {
            throw new ConfigurationException("The default login page requires a local path for quarkus.http.auth.form."
                    + property, exception);
        }
    }

}

package io.quarkiverse.authorization.server.runtime.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.web.RoutingContext;

/** Shared document and fixed stylesheet for the default authorization server browser pages. */
public final class DefaultBrowserPage {

    private static final String STYLES = """
            :root {
              color-scheme: light;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
              color: #18243b; background: #f4f6fa;
              font-synthesis: none; -webkit-font-smoothing: antialiased;
            }
            * { box-sizing: border-box; }
            body { margin: 0; min-width: 0; }
            .page {
              min-height: 100vh; min-height: 100dvh; padding: 48px 20px;
              display: flex; flex-direction: column; align-items: center; justify-content: center;
              background: radial-gradient(ellipse at top, #e8eefc 0, transparent 65%);
            }
            .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 24px;
              font-size: 14px; font-weight: 650; letter-spacing: .02em; }
            .brand-mark { display: grid; place-items: center; width: 30px; height: 30px;
              border-radius: 9px; background: #2854c5; color: white; font-size: 20px; }
            .card { width: 100%; max-width: 460px; padding: 36px;
              border: 1px solid #e0e5ee; border-radius: 20px; background: white;
              box-shadow: 0 12px 40px -20px #1c345340, 0 2px 8px #1c345306; }
            h1 { margin: 0; font-size: 28px; font-weight: 650; letter-spacing: -.035em; line-height: 1.2; }
            .lead { margin: 12px 0 28px; color: #58677e; font-size: 14px; line-height: 1.65; }
            .field { display: block; margin-bottom: 20px; }
            .field label { display: block; margin-bottom: 8px; font-size: 13px; font-weight: 650; }
            .field input { width: 100%; min-height: 46px; padding: 11px 13px;
              border: 1px solid #bdc8d8; border-radius: 9px; background: #fff;
              font: inherit; font-size: 16px; color: inherit; }
            .field input:hover { border-color: #899dbd; }
            input:focus-visible, button:focus-visible { outline: 3px solid #87aaf6; outline-offset: 3px; }
            button { min-height: 46px; padding: 12px 20px; width: 100%;
              border: 1px solid #2854c5; border-radius: 9px; background: #2854c5; color: #fff;
              font: inherit; font-size: 14px; font-weight: 650; cursor: pointer; }
            button:hover { background: #2045a7; border-color: #2045a7; }
            button:active { background: #183888; }
            button.secondary { background: #fff; border-color: #c5cfdd; color: #34425b; }
            button.secondary:hover { background: #f2f5fa; border-color: #a3b3ca; }
            .error { margin: 0 0 24px; padding: 13px 15px; border: 1px solid #f4c7c7;
              border-radius: 9px; background: #fff4f4; color: #a02b2b; font-size: 13px; line-height: 1.6; }
            .details { margin: 0 0 28px; padding: 16px 18px; border: 1px solid #e4e9f1;
              border-radius: 12px; background: #f8faff; }
            .details div + div { margin-top: 15px; }
            dt { margin-bottom: 5px; color: #58677e; font-size: 12px; }
            dd { margin: 0; font-size: 14px; font-weight: 600; line-height: 1.5; overflow-wrap: anywhere; }
            fieldset { border: 0; padding: 0; margin: 0 0 24px; min-width: 0; }
            legend { padding: 0; margin-bottom: 10px; font-size: 13px; font-weight: 650; }
            .scope { display: flex; gap: 12px; align-items: center; min-height: 48px;
              padding: 12px 14px; border: 1px solid #dbe2ed; border-radius: 9px; cursor: pointer; }
            .scope + .scope { margin-top: 8px; }
            .scope:hover { background: #f8faff; }
            .scope input { width: 18px; height: 18px; flex-shrink: 0; margin: 0; accent-color: #2854c5; }
            .scope span { font-size: 14px; line-height: 1.5; overflow-wrap: anywhere; min-width: 0; }
            .scope.granted { background: #f7f9fc; color: #58677e; cursor: default; }
            .device-code { margin: 0 0 24px; padding: 20px; text-align: center;
              border: 1px solid #dbe2ed; border-radius: 12px; background: #f8faff; }
            .device-code span { display: block; margin-bottom: 8px; color: #58677e; font-size: 12px; }
            .device-code strong { display: block; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
              font-size: 28px; letter-spacing: .08em; line-height: 1.4; overflow-wrap: anywhere; }
            .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 28px; }
            .footnote { margin: 24px 0 0; color: #62718a; font-size: 12px; }
            @media (max-width: 480px) {
              .page { padding: 28px 16px; }
              .card { padding: 28px 24px; border-radius: 16px; }
              h1 { font-size: 26px; }
            }
            """;

    private static final String CONTENT_SECURITY_POLICY;

    static {
        try {
            // Authorize only this fixed stylesheet; keep scripts and arbitrary inline styles blocked.
            String hash = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(STYLES.getBytes(StandardCharsets.UTF_8)));
            CONTENT_SECURITY_POLICY = "default-src 'none'; style-src 'sha256-" + hash
                    + "'; frame-ancestors 'none'; base-uri 'none'";
        } catch (NoSuchAlgorithmException exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private DefaultBrowserPage() {
    }

    /** The body is internal HTML whose dynamic values have already been escaped by the form renderer. */
    public static void write(RoutingContext context, String title, String body) {
        DefaultBrowserPage.write(context, title, body, CONTENT_SECURITY_POLICY);
    }

    /** For forms that stay on this origin, unlike authorization code forms that redirect to a client. */
    public static void writeLocalForm(RoutingContext context, String title, String body) {
        DefaultBrowserPage.write(context, title, body, CONTENT_SECURITY_POLICY + "; form-action 'self'");
    }

    private static void write(RoutingContext context, String title, String body, String contentSecurityPolicy) {
        String page = """
                <!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>%s</title><style>%s</style></head><body>
                <div class="page"><header class="brand"><span class="brand-mark" aria-hidden="true">↗</span>
                <span>Account access</span></header><main class="card"><h1>%s</h1>%s</main>
                <p class="footnote">Authorization Server</p></div></body></html>
                """.formatted(DefaultBrowserPage.escapeHtml(title), STYLES,
                DefaultBrowserPage.escapeHtml(title), body);
        context.response()
                .putHeader(HttpHeaders.CONTENT_TYPE, "text/html;charset=UTF-8")
                .putHeader(HttpHeaders.CACHE_CONTROL, "no-store")
                .putHeader("Content-Security-Policy", contentSecurityPolicy)
                .putHeader("X-Content-Type-Options", "nosniff")
                // Preserve the form POST's Origin for CORS without forwarding the authorization query.
                .putHeader("Referrer-Policy", "strict-origin")
                .end(page);
    }

    public static String escapeHtml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}

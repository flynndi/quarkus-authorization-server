package io.quarkiverse.authorization.server.runtime.dpop;

import java.net.URI;
import java.util.ArrayDeque;
import java.util.Locale;
import java.util.Objects;

import io.vertx.ext.web.RoutingContext;

/** HTTP facts captured by the server, never taken from OAuth form parameters. */
public record DPoPProofRequest(String proof, String method, URI uri) {

    public static final String HEADER_NAME = "DPoP";

    public DPoPProofRequest {
        Objects.requireNonNull(proof, "proof");
        Objects.requireNonNull(method, "method");
        uri = canonicalUri(uri);
    }

    /** Absence is optional; a present empty or duplicate header is always invalid. */
    public static DPoPProofRequest ifAvailable(RoutingContext context) {
        return context.request().headers().contains(HEADER_NAME) ? from(context) : null;
    }

    /** Requires exactly one proof. Callers decide separately whether DPoP is required. */
    public static DPoPProofRequest from(RoutingContext context) {
        var values = context.request().headers().getAll(HEADER_NAME);
        if (values.size() != 1 || values.getFirst().isBlank()) {
            throw DPoPProofVerifier.invalidProof();
        }
        // absoluteURI uses Quarkus HTTP's trusted proxy configuration; do not read Forwarded here.
        return new DPoPProofRequest(
                values.getFirst(),
                context.request().method().name(),
                URI.create(context.request().absoluteURI()));
    }

    /** Shared normalization for proof targets and replay-store keys. */
    public static URI canonicalUri(URI uri) {
        Objects.requireNonNull(uri, "uri");
        String scheme = uri.getScheme();
        if (scheme == null
                || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))
                || uri.getHost() == null
                || uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException(
                    "DPoP target must be an absolute HTTP(S) URI without userinfo");
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        int port = uri.getPort();
        if ((scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80))
            port = -1;
        String path = uri.getRawPath();
        path = path == null || path.isEmpty()
                ? "/"
                : removeDotSegments(normalizePercentEncoding(path));
        return URI.create(
                scheme
                        + "://"
                        + uri.getHost().toLowerCase(Locale.ROOT)
                        + (port == -1 ? "" : ":" + port)
                        + path);
    }

    private static String removeDotSegments(String path) {
        // RFC 3986 dot removal preserves empty segments; URI.normalize() also collapses //.
        var output = new ArrayDeque<String>();
        String[] segments = path.split("/", -1);
        for (int i = 1; i < segments.length; i++) {
            String segment = segments[i];
            if (segment.equals("..")) {
                if (!output.isEmpty())
                    output.removeLast();
            } else if (!segment.equals(".")) {
                output.addLast(segment);
                continue;
            }
            if (i == segments.length - 1)
                output.addLast("");
        }
        return "/" + String.join("/", output);
    }

    private static String normalizePercentEncoding(String path) {
        StringBuilder result = new StringBuilder(path.length());
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '%') {
                int value = Integer.parseInt(path.substring(i + 1, i + 3), 16);
                boolean unreserved = value >= 'A' && value <= 'Z'
                        || value >= 'a' && value <= 'z'
                        || value >= '0' && value <= '9'
                        || "-._~".indexOf(value) >= 0;
                result.append(
                        unreserved
                                ? Character.toString((char) value)
                                : path.substring(i, i + 3).toUpperCase(Locale.ROOT));
                i += 2;
            } else
                result.append(c);
        }
        return result.toString();
    }

    @Override
    public String toString() {
        return "DPoPProofRequest[method=" + method + ", uri=" + uri + "]";
    }
}

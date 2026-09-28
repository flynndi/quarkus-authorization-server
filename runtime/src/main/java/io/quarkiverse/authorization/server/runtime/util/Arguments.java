package io.quarkiverse.authorization.server.runtime.util;

/** Internal argument checks shared by models, repositories and protocol parsers. */
public final class Arguments {

    private Arguments() {
    }

    public static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    /** Rejects blank input without trimming or otherwise changing the supplied value. */
    public static String requireNonBlank(String value, String name) {
        if (!Arguments.hasText(value)) {
            throw new IllegalArgumentException(name + " cannot be empty");
        }
        return value;
    }
}

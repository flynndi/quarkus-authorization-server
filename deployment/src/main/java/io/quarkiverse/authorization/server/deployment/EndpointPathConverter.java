package io.quarkiverse.authorization.server.deployment;

import org.eclipse.microprofile.config.spi.Converter;

/** Validates endpoint configuration before it is consumed by route and settings build steps. */
public final class EndpointPathConverter implements Converter<String> {

    @Override
    public String convert(String endpoint) {
        if (endpoint == null
                || endpoint.isBlank()
                || !endpoint.startsWith("/")
                || endpoint.startsWith("//")
                || endpoint.length() == 1
                || endpoint.indexOf('?') >= 0
                || endpoint.indexOf('#') >= 0) {
            throw new IllegalArgumentException(
                    "Authorization Server endpoint must be an absolute path: " + endpoint);
        }
        // Preserve the configured value; route adaptation and root-path resolution happen at their respective boundaries.
        return endpoint;
    }
}

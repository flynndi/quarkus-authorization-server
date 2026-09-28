package io.quarkiverse.authorization.server.runtime.oidc.http.converter;

import java.math.BigDecimal;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

import io.quarkiverse.authorization.server.oidc.OidcClientMetadataClaimNames;
import io.quarkiverse.authorization.server.oidc.OidcClientRegistration;
import io.quarkiverse.authorization.server.runtime.http.converter.AbstractOAuth2HttpMessageConverter;
import io.vertx.core.http.HttpServerResponse;

/**
 * Converts OIDC registration JSON with Jackson, including protocol scope strings
 * and epoch seconds without changing the application's shared ObjectMapper configuration.
 * CDI assembly is limited to the optional registration endpoint.
 */
@Singleton
public final class OidcClientRegistrationHttpMessageConverter extends AbstractOAuth2HttpMessageConverter {

    private final ObjectReader reader;
    private Function<Map<String, Object>, OidcClientRegistration> clientRegistrationConverter = new MapOidcClientRegistrationConverter();
    private Function<OidcClientRegistration, Map<String, Object>> clientRegistrationParametersConverter = new OidcClientRegistrationMapConverter();

    @Inject
    public OidcClientRegistrationHttpMessageConverter(ObjectMapper objectMapper) {
        super(objectMapper);
        this.reader = objectMapper.readerFor(new TypeReference<Map<String, Object>>() {
        })
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public OidcClientRegistration read(String json) {
        try {
            Map<String, Object> parameters = this.reader.readValue(json);
            return this.clientRegistrationConverter.apply(parameters);
        } catch (JsonProcessingException | IllegalArgumentException exception) {
            // The HTTP authentication converter maps an unreadable document to invalid_request.
            throw new IllegalArgumentException("Unable to read the OpenID Client Registration", exception);
        }
    }

    public void write(OidcClientRegistration registration, HttpServerResponse response) {
        writeJson(this.clientRegistrationParametersConverter.apply(registration), response);
    }

    public void setClientRegistrationConverter(Function<Map<String, Object>, OidcClientRegistration> converter) {
        this.clientRegistrationConverter = Objects.requireNonNull(converter, "clientRegistrationConverter cannot be null");
    }

    public void setClientRegistrationParametersConverter(Function<OidcClientRegistration, Map<String, Object>> converter) {
        this.clientRegistrationParametersConverter = Objects.requireNonNull(converter,
                "clientRegistrationParametersConverter cannot be null");
    }

    private static final class MapOidcClientRegistrationConverter
            implements Function<Map<String, Object>, OidcClientRegistration> {

        @Override
        public OidcClientRegistration apply(Map<String, Object> source) {
            if (source == null || source.isEmpty()) {
                throw new IllegalArgumentException("claims cannot be empty");
            }
            Map<String, Object> claims = new LinkedHashMap<>(source);
            for (String claim : new String[] { OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT,
                    OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT }) {
                if (!claims.containsKey(claim)) {
                    continue;
                }
                Object value = claims.get(claim);
                if (!(value instanceof Number)) {
                    throw new IllegalArgumentException(claim + " must contain integer epoch seconds");
                }
                long epoch;
                try {
                    epoch = new BigDecimal(value.toString()).longValueExact();
                } catch (ArithmeticException exception) {
                    throw new IllegalArgumentException(claim + " must contain integer epoch seconds", exception);
                }
                if (epoch < 0) {
                    throw new IllegalArgumentException(claim + " must not be negative");
                }
                if (epoch == 0 && OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT.equals(claim)) {
                    // OIDC uses 0 on the wire for a non-expiring secret; the domain uses null.
                    if (!claims.containsKey(OidcClientMetadataClaimNames.CLIENT_SECRET)) {
                        throw new IllegalArgumentException("client_secret cannot be null");
                    }
                    claims.remove(claim);
                } else {
                    try {
                        claims.put(claim, Instant.ofEpochSecond(epoch));
                    } catch (java.time.DateTimeException exception) {
                        throw new IllegalArgumentException(claim + " is outside the Instant range", exception);
                    }
                }
            }
            if (claims.containsKey(OidcClientMetadataClaimNames.SCOPE)) {
                Object value = claims.get(OidcClientMetadataClaimNames.SCOPE);
                if (!(value instanceof String scope)) {
                    throw new IllegalArgumentException("scope must be a space-delimited String");
                }
                claims.put(OidcClientMetadataClaimNames.SCOPE, Arrays.asList(scope.split(" ", -1)));
            }
            return OidcClientRegistration.withClaims(claims).build();
        }
    }

    private static final class OidcClientRegistrationMapConverter
            implements Function<OidcClientRegistration, Map<String, Object>> {

        @Override
        public Map<String, Object> apply(OidcClientRegistration source) {
            Map<String, Object> claims = new LinkedHashMap<>(source.getClaims());
            if (source.getClientIdIssuedAt() != null) {
                claims.put(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, source.getClientIdIssuedAt().getEpochSecond());
            }
            if (source.getClientSecret() != null) {
                claims.put(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT,
                        source.getClientSecretExpiresAt() == null ? 0L : source.getClientSecretExpiresAt().getEpochSecond());
            }
            if (source.getScopes() != null) {
                claims.put(OidcClientMetadataClaimNames.SCOPE, String.join(" ", source.getScopes()));
            }
            claims.replaceAll((claim, value) -> value instanceof URL url ? url.toExternalForm() : value);
            return claims;
        }
    }
}

package io.quarkiverse.authorization.server.runtime.client.registration.web;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

import io.quarkiverse.authorization.server.client.registration.OAuth2ClientMetadataClaimNames;
import io.quarkiverse.authorization.server.client.registration.OAuth2ClientRegistrationRequest;
import io.quarkiverse.authorization.server.model.AuthorizationGrantType;
import io.quarkiverse.authorization.server.model.ClientAuthenticationMethod;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;
import io.quarkiverse.authorization.server.runtime.client.registration.OAuth2ClientRegistrationService;
import io.quarkus.security.identity.SecurityIdentity;

/** Strict JSON input only; request records never pass through persistence or polymorphic typing. */
public final class OAuth2ClientRegistrationRequestParser {
    private static final Set<String> FIELDS = Set.of(OAuth2ClientMetadataClaimNames.CLIENT_NAME,
            OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, OAuth2ClientMetadataClaimNames.GRANT_TYPES,
            OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, OAuth2ClientMetadataClaimNames.REDIRECT_URIS,
            OAuth2ClientMetadataClaimNames.SCOPE);
    private final ObjectReader reader;

    public OAuth2ClientRegistrationRequestParser(ObjectMapper mapper) {
        this.reader = mapper.readerFor(new TypeReference<Map<String, Object>>() {
        })
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    }

    public OAuth2ClientRegistrationRequest parse(String json, SecurityIdentity principal) {
        try {
            Map<String, Object> values = this.reader.readValue(json);
            if (values == null)
                throw new IllegalArgumentException();
            for (String field : values.keySet()) {
                if (!FIELDS.contains(field))
                    throw OAuth2ClientRegistrationService.invalidMetadata(field);
            }
            String name = OAuth2ClientRegistrationRequestParser.text(values, OAuth2ClientMetadataClaimNames.CLIENT_NAME, null);
            String method = OAuth2ClientRegistrationRequestParser.text(values,
                    OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD,
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
            var grantTypes = new LinkedHashSet<AuthorizationGrantType>();
            for (String grant : OAuth2ClientRegistrationRequestParser.strings(values,
                    OAuth2ClientMetadataClaimNames.GRANT_TYPES,
                    Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())))
                grantTypes.add(new AuthorizationGrantType(grant));
            var responseTypes = OAuth2ClientRegistrationRequestParser.strings(values,
                    OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, Set.of());
            if (!Set.of("code").containsAll(responseTypes))
                throw OAuth2ClientRegistrationService.invalidMetadata(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES);
            // An explicit response_types=code also registers the authorization_code grant.
            if (responseTypes.contains("code"))
                grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
            String scope = OAuth2ClientRegistrationRequestParser.text(values, OAuth2ClientMetadataClaimNames.SCOPE, null);
            Set<String> scopes = scope == null ? Set.of() : new LinkedHashSet<>(Arrays.asList(scope.split(" ", -1)));
            return new OAuth2ClientRegistrationRequest(principal, name, new ClientAuthenticationMethod(method), grantTypes,
                    OAuth2ClientRegistrationRequestParser.strings(values, OAuth2ClientMetadataClaimNames.REDIRECT_URIS,
                            Set.of()),
                    scopes);
        } catch (com.fasterxml.jackson.core.JsonProcessingException | IllegalArgumentException failure) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
    }

    private static String text(Map<String, Object> values, String name, String fallback) {
        if (!values.containsKey(name))
            return fallback;
        if (!(values.get(name) instanceof String value) || value.isBlank())
            throw new IllegalArgumentException();
        return value;
    }

    private static Set<String> strings(Map<String, Object> values, String name, Set<String> fallback) {
        if (!values.containsKey(name))
            return fallback;
        if (!(values.get(name) instanceof List<?> list))
            throw new IllegalArgumentException();
        Set<String> strings = new LinkedHashSet<>();
        for (Object entry : list) {
            if (!(entry instanceof String value) || value.isBlank())
                throw new IllegalArgumentException();
            strings.add(value);
        }
        return strings;
    }
}

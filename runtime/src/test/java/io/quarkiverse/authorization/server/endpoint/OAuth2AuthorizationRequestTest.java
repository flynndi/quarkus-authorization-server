package io.quarkiverse.authorization.server.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.model.AuthorizationGrantType;

class OAuth2AuthorizationRequestTest {

    @Test
    void buildsAuthorizationCodeRequestWithOrderedAndEncodedParameters() {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com/oauth2/authorize")
                .clientId("client-id")
                .redirectUri("https://client.example.com/callback")
                .scope("message.read", "message.write")
                .state("request state")
                .additionalParameters(parameters -> parameters.put("code_challenge", "challenge/value"))
                .attributes(attributes -> attributes.put("request-id", "request-1"))
                .build();

        assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, authorizationRequest.getGrantType());
        assertEquals(OAuth2AuthorizationResponseType.CODE, authorizationRequest.getResponseType());
        assertEquals(Set.of("message.read", "message.write"), authorizationRequest.getScopes());
        assertEquals("request-1", authorizationRequest.getAttribute("request-id"));
        assertEquals("https://auth.example.com/oauth2/authorize?response_type=code&client_id=client-id"
                + "&scope=message.read%20message.write&state=request%20state"
                + "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback"
                + "&code_challenge=challenge%2Fvalue",
                authorizationRequest.getAuthorizationRequestUri());
        assertThrows(UnsupportedOperationException.class,
                () -> authorizationRequest.getScopes().add("message.delete"));
        assertThrows(UnsupportedOperationException.class,
                () -> authorizationRequest.getAttributes().put("other", "value"));
    }

    @Test
    void supportsExplicitAndCustomizedAuthorizationRequestUri() {
        OAuth2AuthorizationRequest explicit = requestBuilder()
                .authorizationRequestUri("https://client.example.com/prebuilt")
                .build();
        OAuth2AuthorizationRequest customized = requestBuilder()
                .authorizationRequestUri(uri -> URI.create(uri + "&custom=true"))
                .build();

        assertEquals("https://client.example.com/prebuilt", explicit.getAuthorizationRequestUri());
        assertEquals("https://auth.example.com/oauth2/authorize?response_type=code&client_id=client-id&custom=true",
                customized.getAuthorizationRequestUri());
    }

    @Test
    void appendsParametersToExistingAuthorizationUriQuery() {
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com/oauth2/authorize?prompt=login")
                .clientId("client-id")
                .build();

        assertEquals("https://auth.example.com/oauth2/authorize?prompt=login"
                + "&response_type=code&client_id=client-id",
                authorizationRequest.getAuthorizationRequestUri());
    }

    @Test
    void copiesRequestAndValidatesRequiredValues() {
        OAuth2AuthorizationRequest authorizationRequest = requestBuilder()
                .scope("message.read")
                .build();
        OAuth2AuthorizationRequest copy = OAuth2AuthorizationRequest.from(authorizationRequest).build();

        assertEquals(authorizationRequest.getGrantType(), copy.getGrantType());
        assertEquals(authorizationRequest.getResponseType(), copy.getResponseType());
        assertEquals(authorizationRequest.getAuthorizationRequestUri(), copy.getAuthorizationRequestUri());
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2AuthorizationRequest.authorizationCode().clientId("client-id").build());
        assertThrows(IllegalArgumentException.class,
                () -> OAuth2AuthorizationRequest.authorizationCode()
                        .authorizationUri("https://auth.example.com/oauth2/authorize").build());
    }

    private static OAuth2AuthorizationRequest.Builder requestBuilder() {
        return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://auth.example.com/oauth2/authorize")
                .clientId("client-id");
    }
}

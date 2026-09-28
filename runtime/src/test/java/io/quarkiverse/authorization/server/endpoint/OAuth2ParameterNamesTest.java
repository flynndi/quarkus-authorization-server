package io.quarkiverse.authorization.server.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class OAuth2ParameterNamesTest {

    @Test
    void exposesOAuth2ProtocolParameterNames() {
        assertEquals("grant_type", OAuth2ParameterNames.GRANT_TYPE);
        assertEquals("response_type", OAuth2ParameterNames.RESPONSE_TYPE);
        assertEquals("client_id", OAuth2ParameterNames.CLIENT_ID);
        assertEquals("client_secret", OAuth2ParameterNames.CLIENT_SECRET);
        assertEquals("client_assertion_type", OAuth2ParameterNames.CLIENT_ASSERTION_TYPE);
        assertEquals("client_assertion", OAuth2ParameterNames.CLIENT_ASSERTION);
        assertEquals("assertion", OAuth2ParameterNames.ASSERTION);
        assertEquals("redirect_uri", OAuth2ParameterNames.REDIRECT_URI);
        assertEquals("scope", OAuth2ParameterNames.SCOPE);
        assertEquals("state", OAuth2ParameterNames.STATE);
        assertEquals("code", OAuth2ParameterNames.CODE);
        assertEquals("access_token", OAuth2ParameterNames.ACCESS_TOKEN);
        assertEquals("token_type", OAuth2ParameterNames.TOKEN_TYPE);
        assertEquals("expires_in", OAuth2ParameterNames.EXPIRES_IN);
        assertEquals("refresh_token", OAuth2ParameterNames.REFRESH_TOKEN);
        assertEquals("username", OAuth2ParameterNames.USERNAME);
        assertEquals("password", OAuth2ParameterNames.PASSWORD);
        assertEquals("error", OAuth2ParameterNames.ERROR);
        assertEquals("error_description", OAuth2ParameterNames.ERROR_DESCRIPTION);
        assertEquals("error_uri", OAuth2ParameterNames.ERROR_URI);
        assertEquals("registration_id", OAuth2ParameterNames.REGISTRATION_ID);
        assertEquals("token", OAuth2ParameterNames.TOKEN);
        assertEquals("token_type_hint", OAuth2ParameterNames.TOKEN_TYPE_HINT);
        assertEquals("device_code", OAuth2ParameterNames.DEVICE_CODE);
        assertEquals("user_code", OAuth2ParameterNames.USER_CODE);
        assertEquals("verification_uri", OAuth2ParameterNames.VERIFICATION_URI);
        assertEquals("verification_uri_complete", OAuth2ParameterNames.VERIFICATION_URI_COMPLETE);
        assertEquals("interval", OAuth2ParameterNames.INTERVAL);
        assertEquals("audience", OAuth2ParameterNames.AUDIENCE);
        assertEquals("resource", OAuth2ParameterNames.RESOURCE);
        assertEquals("requested_token_type", OAuth2ParameterNames.REQUESTED_TOKEN_TYPE);
        assertEquals("issued_token_type", OAuth2ParameterNames.ISSUED_TOKEN_TYPE);
        assertEquals("subject_token", OAuth2ParameterNames.SUBJECT_TOKEN);
        assertEquals("subject_token_type", OAuth2ParameterNames.SUBJECT_TOKEN_TYPE);
        assertEquals("actor_token", OAuth2ParameterNames.ACTOR_TOKEN);
        assertEquals("actor_token_type", OAuth2ParameterNames.ACTOR_TOKEN_TYPE);
    }
}

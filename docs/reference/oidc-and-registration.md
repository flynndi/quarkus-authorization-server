# OIDC and registration

Paths assume the default endpoints and HTTP root. [Server configuration](./configuration) lists the required build-time switches; [OAuth endpoints](./endpoints) covers Code, token, PAR and device requests.

## OIDC endpoints {#oidc-endpoints}

Enable `quarkus.authorization-server.oidc.enabled=true`. Clients also need the relevant `openid` scope, redirects and grants.

<div class="reference-table" role="region" aria-label="OIDC endpoint table; scroll horizontally if needed" tabindex="0">

| Method and default path | Input and authentication | Result |
| --- | --- | --- |
| `GET /.well-known/openid-configuration` | Public; no body | `200` JSON provider metadata; in multi-issuer mode this path follows the issuer path |
| `GET /userinfo`, `POST /userinfo` | `Authorization: Bearer …` or `Authorization: DPoP …`; bound tokens also need a `DPoP` proof header | `200` JSON claims |
| `GET /connect/logout` | Query; required `id_token_hint` | `302` to validated post-logout URI or `/` |
| `POST /connect/logout` | Form; same parameters as GET | Same logout result |

</div>

### UserInfo {#userinfo}

UserInfo reads tokens only from the `Authorization` header, not query or form `access_token`. POST does not define a JSON/form request payload. The server requires an active stored access token with `openid` and a corresponding authorization with an ID Token. A DPoP-bound token cannot be consumed as Bearer; its proof must match the key, request method/URI and access-token hash (`ath`).

```bash
curl --header 'Authorization: Bearer REPLACE_WITH_OPENID_ACCESS_TOKEN' \
  'http://localhost:8080/userinfo'
```

[DefaultOidcUserInfoMapper] selects claims from the stored ID Token using the granted scopes: `sub` plus applicable `profile`, `email`, `phone`, `address`, `groups` and `perms` claims. It does not reload the user or create claims missing from that ID Token. Applications may replace `OidcUserInfoMapper`. The response is JSON; signed/encrypted UserInfo responses are not implemented.

Typical errors are `401 invalid_token`, `403 insufficient_scope` and `400 invalid_request`; authentication/authorization failures include the relevant challenge. Internal mapping failures use `500 server_error`. See [OidcUserInfoAuthenticationMechanism], [OidcUserInfoEndpointHandler] and [OidcUserInfoService].

### RP-Initiated Logout {#logout}

`id_token_hint` is mandatory. Optional single-value parameters are `client_id`, `post_logout_redirect_uri` and `state`. The service validates the hint, client, user/session context and registered redirect; `state` is returned with an accepted post-logout redirect. An anonymous browser can submit a valid hint, but this does not invent an authenticated session to terminate.

The default `OidcSessionManager` integrates with Quarkus Form. Logout ends the matching browser session; it does not revoke issued access/refresh tokens or stored consent. Missing/invalid parameters return JSON `400`; wrong POST form media type returns `415`. There is no logout without a hint, front-channel logout or back-channel logout implementation. See [OidcLogoutRequestParser], [OidcLogoutService] and [OidcLogoutEndpointHandler].

## Registration endpoints {#registration-endpoints}

These are two separate contracts. Both accept JSON (`application/json` or `application/*+json`), return `201` on creation, and reject unsupported metadata. Form POST is not accepted.

<div class="reference-table" role="region" aria-label="Registration endpoint table; scroll horizontally if needed" tabindex="0">

| Endpoint | Enablement and credentials | Result / management |
| --- | --- | --- |
| `POST /oauth2/register` | `client-registration.enabled=true`; Bearer initial access token. Anonymous requests additionally require `client-registration.open-registration-allowed=true`. | Client metadata and a secret when applicable; no registration access token or management GET/PUT/DELETE |
| `POST /connect/register` | `oidc.enabled=true` and `oidc.client-registration.enabled=true`; Bearer initial access token required | Metadata, optional client secret, `registration_access_token`, `registration_client_uri` |
| `GET /connect/register?client_id=…` | Same OIDC switches; Bearer registration access token bound to this client | `200` metadata, without the client secret; no PUT/DELETE |

</div>

The two registration paths must differ when both are enabled. Open OAuth registration does not enable anonymous OIDC registration. If a caller supplies invalid credentials to the open endpoint, the request still fails; it does not fall back to anonymous registration.

### Initial and registration access tokens {#registration-tokens}

An initial token must be an active, locally stored Bearer access token whose scope set is **exactly** `client.create`. A successful protected registration invalidates this initial authorization's access token and refresh token, if present. A token containing `client.create` plus other scopes is rejected. The application provisions the initial token; registration does not provide an anonymous bootstrap-token endpoint.

OIDC returns a separate registration access token with exactly `client.read`, bound to the new client for configuration reads. Its generation does not add the Client Credentials grant to that client's allowed grants. Reserved `client.create` / `client.read` scopes cannot be requested as the new client's scopes. See [RegistrationAccessTokens] and [OidcClientRegistrationService].

### Accepted metadata {#registration-metadata}

| Contract | Accepted request fields |
| --- | --- |
| Both | `client_name`, `token_endpoint_auth_method`, `grant_types`, `response_types`, `redirect_uris`, `scope` |
| OIDC only | `post_logout_redirect_uris`, `jwks_uri`, `tls_client_auth_subject_dn`, `token_endpoint_auth_signing_alg`, `id_token_signed_response_alg` |

`scope` is a space-separated string; URI, grant and response lists are JSON arrays. Client IDs, secrets and registration credentials are generated by the server, not accepted as request metadata. Unknown fields are not silently persisted.

OAuth registration accepts only `client_secret_basic`, `client_secret_post` and `none`; the default is `client_secret_basic`. Absent grants default to `authorization_code`. Only `code` is supported as a response type. Code clients require redirect URIs. Public clients are limited to Code, Device and Refresh grants in this registration contract.

OIDC registration accepts the seven [client authentication methods](./endpoints#client-authentication), with method-specific metadata constraints: `private_key_jwt` and `self_signed_tls_client_auth` require `jwks_uri`; `tls_client_auth` requires the subject DN; assertion signing algorithms must match their method. Defaults include Basic authentication, Code when grant/response metadata implies it, `RS256` for ID Tokens, `RS256` for private-key assertions and `HS256` for secret assertions. Supply explicit grant/response arrays when the Code defaults are inappropriate.

Both default to PKCE and consent enabled. **The default scope policy rejects nonempty requested scopes.** Provide a `ClientRegistrationScopeValidator` bean to configure scope admission for both default request validators while retaining URI checks. Static-client configuration does not set a dynamic registration scope policy. See the [CDI reference](./extensions#registration-policy). Fixed metadata/capability checks still run.

Secret-bearing registration returns the generated plaintext secret at creation. The default encoder stores a bcrypt value except for `client_secret_jwt`, which needs usable shared-key material. Do not expect configuration reads to reveal a secret. Implementation: [OAuth2ClientRegistrationRequestParser], [OAuth2ClientRegistrationService], [OidcClientRegistrationMetadataValidator] and [OidcClientRegistrationRegisteredClientConverter].

### Example and errors {#registration-example}

This protected OAuth example intentionally requests no scopes, so it works with the default scope validator once a valid initial token is provisioned:

```bash
curl --header 'Authorization: Bearer REPLACE_WITH_INITIAL_ACCESS_TOKEN' \
  --header 'Content-Type: application/json' \
  --data '{"client_name":"Machine demo","token_endpoint_auth_method":"client_secret_basic","grant_types":["client_credentials"],"response_types":[]}' \
  'http://localhost:8080/oauth2/register'
```

An open-registration deployment can omit the Authorization header. Its client persistence and scope policy still apply.

Typical statuses are `400 invalid_request`, `invalid_client_metadata`, `invalid_redirect_uri` or `invalid_scope`; `401 invalid_token`; `403 insufficient_scope`; `415` for the wrong media type; and `500 server_error`. A token missing the required scope and a token with extra scopes are distinct failures. Client persistence, registration-token persistence and initial-token invalidation are separate writes by default: a `500` does not guarantee that nothing was saved. See [protocol boundaries](./protocol-support#storage).

## Source and existing coverage {#evidence}

Source links are pinned to the audited commit. Existing coverage includes [OidcUserInfoEndpointTest], [OidcLogoutEndpointTest], [OAuthClientRegistrationEndpointTest], [OAuthClientRegistrationOpenTest] and [OidcClientRegistrationPolicyTest]. These tests distinguish protected/open registration and validate failure behavior; they were not rerun as part of this documentation-only change.

[DefaultOidcUserInfoMapper]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/userinfo/DefaultOidcUserInfoMapper.java
[OAuth2ClientRegistrationRequestParser]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/registration/web/OAuth2ClientRegistrationRequestParser.java
[OAuth2ClientRegistrationService]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/registration/OAuth2ClientRegistrationService.java
[OAuthClientRegistrationEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/OAuthClientRegistrationEndpointTest.java
[OAuthClientRegistrationOpenTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/OAuthClientRegistrationOpenTest.java
[OidcClientRegistrationMetadataValidator]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/registration/OidcClientRegistrationMetadataValidator.java
[OidcClientRegistrationPolicyTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/OidcClientRegistrationPolicyTest.java
[OidcClientRegistrationRegisteredClientConverter]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/converter/OidcClientRegistrationRegisteredClientConverter.java
[OidcClientRegistrationService]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/registration/OidcClientRegistrationService.java
[OidcLogoutEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/web/OidcLogoutEndpointHandler.java
[OidcLogoutEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/OidcLogoutEndpointTest.java
[OidcLogoutRequestParser]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/web/OidcLogoutRequestParser.java
[OidcLogoutService]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/logout/OidcLogoutService.java
[OidcUserInfoAuthenticationMechanism]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/web/OidcUserInfoAuthenticationMechanism.java
[OidcUserInfoEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/web/OidcUserInfoEndpointHandler.java
[OidcUserInfoEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/OidcUserInfoEndpointTest.java
[OidcUserInfoService]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/oidc/userinfo/OidcUserInfoService.java
[RegistrationAccessTokens]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/registration/RegistrationAccessTokens.java

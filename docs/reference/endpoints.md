# OAuth endpoints

This page describes the installed HTTP contract. Paths below assume the default endpoints, one issuer and `quarkus.http.root-path=/`. Use discovery when paths are customized; see [server configuration](./configuration) for switches, HTTP roots and multi-issuer discovery paths. Routes are installed by [AuthorizationServerRecorder].

## Endpoint index {#endpoint-index}

“Form” means `application/x-www-form-urlencoded`; “client” means the [client authentication](#client-authentication) mechanism, not a signed-in person. Optional features are absent until their build-time switch is enabled.

<div class="reference-table" role="region" aria-label="Endpoint table; scroll horizontally if needed" tabindex="0">

| Method and default path | Input and authentication | Success |
| --- | --- | --- |
| `GET /.well-known/oauth-authorization-server` | Public; no body | `200` JSON server metadata |
| `GET /oauth2/jwks` | Public; no body | `200` public JWK Set |
| `GET /oauth2/authorize` | Query; protocol validation before a user login challenge | Login, consent HTML or `302` with code |
| `POST /oauth2/authorize` | Form; initial OIDC/PAR request or authenticated consent submission | Login continuation, consent HTML or `302` with code |
| `POST /oauth2/token` | Form; client | `200` JSON token response |
| `POST /oauth2/introspect` | Form; client | `200` JSON with `active` |
| `POST /oauth2/revoke` | Form; client | `200`, empty body |
| `POST /oauth2/device_authorization` | Form; client | `200` JSON device/user codes |
| `GET /oauth2/device_verification` | Query; user login required | Code-entry or confirmation HTML |
| `POST /oauth2/device_verification` | Form; authenticated user | Confirmation or completion HTML |
| `POST /oauth2/par` | Form; client; `pushed-authorization-requests-enabled=true` | `201` JSON reference and lifetime |

</div>

OIDC discovery, UserInfo, logout and both registration endpoints are covered in [OIDC and registration](./oidc-and-registration). The optional default login page follows Quarkus Form configuration; it is not a fixed OAuth endpoint.

## Client authentication {#client-authentication}

The token, introspection, revocation, device authorization and PAR endpoints use [OAuth2ClientAuthenticationMechanism]. Configure the method on `RegisteredClient`:

| Method | Request credentials |
| --- | --- |
| `client_secret_basic` | HTTP Basic header |
| `client_secret_post` | Form `client_id` and `client_secret` |
| `private_key_jwt`, `client_secret_jwt` | Form `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion` |
| `tls_client_auth`, `self_signed_tls_client_auth` | TLS client certificate and form `client_id` |
| `none` | Form `client_id`; identifies a public client without proving a secret |

Introspection, revocation, Client Credentials, Password and Token Exchange require client credentials; public `none` identification is insufficient.

Use one authentication method per request. Mixed credentials and duplicate credential parameters are rejected. Public identification does not authorize every grant: each service still enforces its client, PKCE and token-binding requirements. Authentication failures generally return `401 invalid_client`; malformed authentication requests can return `400 invalid_request`. See [registered clients](./clients) for secret representation, assertion algorithms, JWK URLs and TLS requirements.

## Authorization and consent {#authorization}

An initial request uses `response_type=code`, required `client_id`, optional space-separated `scope` and opaque client `state`. Supply the registered `redirect_uri`; omission is resolved only for a non-OIDC request with exactly one registered URI. OIDC requests require it. PKCE uses `code_challenge` with `code_challenge_method=S256`; public Code clients require PKCE. OIDC requests include `openid` in `scope` and may supply `nonce` and `prompt`. Optional `dpop_jkt` pre-binds the Code flow to a DPoP key thumbprint; it must be a 43-character base64url value and match the proof at exchange.

Use GET for the normal browser request. Initial form POST is recognized for OIDC requests with `response_type` and `openid`, or for a PAR `request_uri`. It is not a general OAuth POST alternative. A validated initial POST that needs login is converted to a query URL with `303` so Quarkus Form can restore it after authentication. [AuthorizationRequestParser] and [OAuth2AuthorizationEndpointHandler] define this distinction.

```bash
curl -i --get 'http://localhost:8080/oauth2/authorize' \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=web' \
  --data-urlencode 'redirect_uri=http://localhost:5173/callback' \
  --data-urlencode 'scope=openid profile' \
  --data-urlencode 'state=replace-with-random-client-state' \
  --data-urlencode 'nonce=replace-with-random-nonce' \
  --data-urlencode 'code_challenge=REPLACE_WITH_S256_CHALLENGE' \
  --data-urlencode 'code_challenge_method=S256'
```

This illustrates the request, not an authenticated browser session. The `web` client, redirects, scopes and OIDC must be configured first. The [Code guide](/guide/authorization-code) provides the runnable browser flow.

Client, response type, redirect, scopes and PKCE are checked before login. An error redirects only to a URI that the server has validated; otherwise it returns JSON `400`. Typical errors are `invalid_request`, `invalid_scope`, `unauthorized_client` and `unsupported_response_type`. OIDC `prompt=none` returns `login_required` or `consent_required` when silent completion is impossible; `none` cannot be combined with another prompt. It does not add a complete reauthentication/account-selection workflow.

A consent submission is a separate form POST to the same endpoint, without `response_type` or `request_uri`:

| Parameter | Contract |
| --- | --- |
| `client_id`, `state` | Required single values from the pending consent context. This `state` is internal pending-request state, not the client's original state. |
| `scope` | Optional repeated fields, one selected scope per value. This differs from the initial request's space-separated scope string. |
| `consent_action` | Optional single `approve` or `deny`; omission means `approve`. |

The submission must match the authenticated user and pending request. `AuthorizationConsentCustomizer` may change the decision and authorities before persistence. Final denial returns `access_denied` and consumes the pending request; existing consent is retained unless its authorities are cleared. Clearing all authorities removes existing consent regardless of the decision. See [ConsentSubmissionParser], [AuthorizationConsentContext] and the [CDI reference](./extensions#ordered-components).

## Token grants {#token-grants}

Every token request needs one nonblank `grant_type`, the client's configured authentication and the corresponding registered grant. Single-value parameters reject duplicates. The grant adapters are selected by [OAuth2TokenEndpointHandler].

<div class="reference-table" role="region" aria-label="Grant parameter table; scroll horizontally if needed" tabindex="0">

| `grant_type` | Required grant parameters | Optional parameters and constraints |
| --- | --- | --- |
| `authorization_code` | `code` | `redirect_uri` must match the original request when it was supplied; PKCE `code_verifier` must match the challenge. Code must belong to the client and remain valid. |
| `refresh_token` | `refresh_token` | `scope` may narrow the original scopes; omission retains them. Bound refresh requires a proof with the same DPoP key. |
| `client_credentials` | None | Space-separated `scope`, limited to registered scopes. Omission produces an empty scope set. No refresh token. |
| `password` | `username`, `password` | Space-separated `scope`. Uses the application's Quarkus password identity provider; no DPoP support. |
| `urn:ietf:params:oauth:grant-type:device_code` | `device_code` | The device must be approved, valid and bound to this client. |
| `urn:ietf:params:oauth:grant-type:token-exchange` | `subject_token`, `subject_token_type` | Paired `actor_token` / `actor_token_type`; `requested_token_type`, `scope`, repeated `resource` and `audience`. |

</div>

Token Exchange accepts the token-type URNs `urn:ietf:params:oauth:token-type:access_token` and `urn:ietf:params:oauth:token-type:jwt`; the requested output type defaults to `access_token`. Inputs must resolve to active local authorizations. A subject needs a resource-owner identity; a Client Credentials token may serve as an actor, not a user subject. When `may_act` is present, an `actor_token` is required and its stored `iss` / `sub` claims must exactly match `may_act`, including whether each claim is present. Use the actor token's customized subject, not its authorization's login name; include `may_act.iss` when the actor token has an issuer. This is not an arbitrary external JWT exchange endpoint. See [TokenExchangeRequestParser] and [TokenExchangeGrant].

```bash
curl --user 'machine:REPLACE_WITH_CLIENT_SECRET' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=message.read' \
  'http://localhost:8080/oauth2/token'
```

The response contains `access_token`, `token_type`, expiry and, when nonempty, `scope`, plus `refresh_token`, OIDC `id_token` or Token Exchange `issued_token_type` when applicable. DPoP uses a `DPoP` proof header and returns `token_type=DPoP` on supported bound flows; see [DPoP](./dpop) and [refresh boundaries](./protocol-support#tokens).

Typical errors: `invalid_request`, `invalid_client`, `unauthorized_client`, `invalid_grant`, `invalid_scope`, `unsupported_grant_type`, `unsupported_token_type`, `invalid_dpop_proof`. Device polling also returns `authorization_pending`, `access_denied` or `expired_token`. Wrong form media type returns `415`; protocol errors after client authentication use `400`. Authentication can fail before media-type checks. Do not depend on every failure producing a JSON body or on all internal failures using `500`.

## Introspection and revocation {#token-management}

Both accept required `token` and optional `token_type_hint`, each as a single form value. The hint does not restrict the current repository lookup.

```bash
curl --user 'resource-client:REPLACE_WITH_CLIENT_SECRET' \
  --data-urlencode 'token=REPLACE_WITH_ACCESS_TOKEN' \
  'http://localhost:8080/oauth2/introspect'

curl --user 'machine:REPLACE_WITH_CLIENT_SECRET' \
  --data-urlencode 'token=REPLACE_WITH_OWN_TOKEN' \
  --data-urlencode 'token_type_hint=access_token' \
  'http://localhost:8080/oauth2/revoke'
```

[OAuth2TokenIntrospectionAuthenticationProvider] returns `{"active":false}` for unknown/inactive tokens. Active responses use stored token claims and metadata. The current provider does **not** restrict introspection to the issuing client or enforce a resource-specific audience policy; client authentication alone is the built-in gate.

[OAuth2TokenRevocationAuthenticationProvider] treats an unknown token as successful revocation, but a known token must belong to the authenticated client. A client mismatch returns `invalid_client`. Revocation changes stored authorization state; an external resource server doing offline JWT validation does not automatically observe it. Missing/duplicate parameters return `400 invalid_request`; form media mismatches return `415` after authentication.

## Device flow {#device-flow}

Device authorization accepts optional space-separated `scope`. Public clients send `client_id`; confidential clients authenticate normally. Its JSON contains `device_code`, `user_code`, `verification_uri`, `verification_uri_complete` and `expires_in`. The current response omits `interval`; there is no implemented polling throttle / `slow_down` response. Client behavior must not assume the server enforces a polling rate.

The user opens `verification_uri` to enter a code, or `verification_uri_complete` with `user_code`. GET and a form POST containing `user_code` can prepare confirmation; they do not approve the device. Confirmation POST requires single `client_id`, `user_code`, internal `state`, `approved=true` or `false`, and optional repeated `scope`. The state binds the user, client and device. Explicit rejection cannot be turned into approval by `DeviceConsentCustomizer`, unlike the Code consent decision hook.

The default page reports completion locally; the device obtains tokens by polling `/oauth2/token`. Invalid or mismatched submissions return an error page, typically `400`; unexpected verification failures use `500`. See [OAuth2DeviceVerificationEndpointHandler] and [DeviceConsentSubmissionParser].

## Pushed Authorization Requests {#par}

PAR accepts the initial authorization parameters as form data plus client authentication. It does not log in the resource owner. `request` (JAR) and nested `request_uri` are rejected.

```bash
curl --user 'web-confidential:REPLACE_WITH_CLIENT_SECRET' \
  --data-urlencode 'client_id=web-confidential' \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'redirect_uri=http://localhost:5173/callback' \
  --data-urlencode 'scope=openid profile' \
  --data-urlencode 'state=replace-with-random-client-state' \
  --data-urlencode 'code_challenge=REPLACE_WITH_S256_CHALLENGE' \
  --data-urlencode 'code_challenge_method=S256' \
  'http://localhost:8080/oauth2/par'

curl -i --get 'http://localhost:8080/oauth2/authorize' \
  --data-urlencode 'client_id=web-confidential' \
  --data-urlencode 'request_uri=REPLACE_WITH_RETURNED_REQUEST_URI'
```

The `201` response supplies `request_uri` and `expires_in=300`. Only the stored request controls redirects, scopes, state and prompt; outer query parameters cannot override it. The reference is checked for client, expiry and current client policy. Login and silent-error responses preserve the reference. Creating pending consent consumes it and continues with the internal consent state; direct code issuance also consumes it. Ordinary authorization remains available: there is no per-client mandatory-PAR setting.

Typical failures include `invalid_request`, `invalid_scope` and `invalid_client`. PAR returns errors as JSON, never as a browser redirect; unsupported methods return `405`, wrong media type `415`, internal failure `500`. Browser-side reference errors follow the authorize endpoint's validated-redirect rule. Implementation: [PushedAuthorizationEndpointHandler] and [PushedAuthorizationRequests].

## Source and existing coverage {#evidence}

Source links on this page are pinned to the audited commit. Existing endpoint coverage includes [AuthorizationEndpointTest], [TokenEndpointTest], [OAuth2DeviceAuthorizationEndpointTest] and [PushedAuthorizationEndpointTest]. These links identify implementation evidence; a documentation build is not a fresh execution of those tests.

[AuthorizationConsentContext]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/authorizationcode/AuthorizationConsentContext.java
[AuthorizationEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/AuthorizationEndpointTest.java
[AuthorizationRequestParser]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/AuthorizationRequestParser.java
[AuthorizationServerRecorder]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/AuthorizationServerRecorder.java
[ConsentSubmissionParser]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/ConsentSubmissionParser.java
[DeviceConsentSubmissionParser]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/devicecode/web/DeviceConsentSubmissionParser.java
[OAuth2AuthorizationEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/OAuth2AuthorizationEndpointHandler.java
[OAuth2ClientAuthenticationMechanism]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/web/OAuth2ClientAuthenticationMechanism.java
[OAuth2DeviceAuthorizationEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/OAuth2DeviceAuthorizationEndpointTest.java
[OAuth2DeviceVerificationEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/devicecode/web/OAuth2DeviceVerificationEndpointHandler.java
[OAuth2TokenEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/web/OAuth2TokenEndpointHandler.java
[OAuth2TokenIntrospectionAuthenticationProvider]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/introspection/authentication/OAuth2TokenIntrospectionAuthenticationProvider.java
[OAuth2TokenRevocationAuthenticationProvider]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/revocation/authentication/OAuth2TokenRevocationAuthenticationProvider.java
[PushedAuthorizationEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/PushedAuthorizationEndpointHandler.java
[PushedAuthorizationEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/PushedAuthorizationEndpointTest.java
[PushedAuthorizationRequests]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/authorization/PushedAuthorizationRequests.java
[TokenEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/TokenEndpointTest.java
[TokenExchangeGrant]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/tokenexchange/TokenExchangeGrant.java
[TokenExchangeRequestParser]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/tokenexchange/web/TokenExchangeRequestParser.java

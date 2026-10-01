# Identity and access

An OAuth request can involve both a client and a user. Keep their identities and permissions separate even when the authorization server and resource API share one Quarkus process.

## Own your user model

The browser example has an application-owned `User` record containing a username, password hash, roles and permissions. `UserService` retrieves it. The extension does not require an authorization-server-specific user entity or user table.

[`ResourceOwnerIdentityProviders`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/config/ResourceOwnerIdentityProviders.java) adapts this model to two Quarkus request types:

| Request | When it is used | What the provider does |
| --- | --- | --- |
| `UsernamePasswordAuthenticationRequest` | Form password submission; also the Password grant | Look up the user, verify the password and build `SecurityIdentity` |
| `TrustedAuthenticationRequest` | A later request with a valid Quarkus Form cookie | Look up the user by the trusted principal and rebuild `SecurityIdentity` |

Both adapters belong to the authorization server and reuse the same user service. The trusted request follows Form cookie validation; it is not an endpoint accepting an arbitrary username as proof of login.

The example's password check uses `AuthenticationRequestContext.runBlocking`. Its trusted lookup is currently in-memory. If your lookup uses blocking JDBC, execute that work through the authentication request context too. Applications using another Quarkus identity integration may already have providers for these request types; do not register duplicate providers blindly.

Sources: [`User`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/user/User.java), [`UserService`](https://github.com/flynndi/quarkus-authorization-server/blob/main/examples/authorization-code/src/main/java/io/quarkiverse/authorization/server/example/authorizationcode/authorizationserver/service/UserService.java).

## Resource-server identity is built from the token

For `/api/messages`, `quarkus-oidc` verifies the access token and constructs the resource-side `SecurityIdentity`. It does not call the two application user providers above. The example explicitly selects Bearer authentication for `/api/*`, so the authorization-server Form cookie does not authenticate this API.

Client Credentials has no end-user identity: its subject is the registered client. Authorization Code has a user subject, while the OAuth client is independently authenticated or identified according to its registered method.

## Scopes, roles and permissions

| Concept | Meaning | Where it is enforced |
| --- | --- | --- |
| Registered client scopes | Scopes this client is allowed to request | Authorization server |
| Authorized scopes | Scopes granted to this authorization after protocol and policy checks | Token issuance and resource-server scope checks |
| User roles / permissions | The application's own user authorization model | Application policy and, if deliberately mapped to claims, resource-server policy |
| Resource ownership / business rules | Whether this subject may act on this particular record | Resource API |

There is no automatic intersection between client scopes and arbitrary user permissions. For example, `message.read` in the client registration means the client may ask for that scope; it does not prove that the user owns every message. Consent records the user's approval, not a replacement for business authorization.

The default JWT generator writes authorized scopes to `scope`. The example uses `quarkus-oidc` to map those scopes into permissions and checks `@PermissionsAllowed("message.read")`. Use resource-side ownership checks as well when access depends on the requested data.

When a token needs application roles, add an explicit claim through a [token customizer](./tokens-and-resources#add-application-claims). Choose which roles belong in the token rather than serializing the whole user object. `@RolesAllowed` and `@PermissionsAllowed` express different checks; configuring one does not automatically implement the other.

## Identity changes after authorization

Authorization records can retain a historical `SecurityIdentity`. The JDBC representation preserves the principal, roles and selected protocol attributes; it does not persist credentials, arbitrary attributes or permission checkers.

Consequently, refreshing a token does not automatically reload current user roles or account status. If immediate revocation or fresh entitlements are required, implement that policy with your user service and token/resource checks. A claim copied from the authorization is a snapshot, not a live user-directory query.

See [`JdbcJsonCodec`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/jdbc/JdbcJsonCodec.java) and [storage and signing keys](./storage-and-keys).

Default implementations, qualifiers and composition rules are indexed in [CDI extension points](/reference/extensions).

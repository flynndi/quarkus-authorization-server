# CDI extension points

Use Quarkus Config for external values and CDI for behavior. There is no extra configuration DSL. Providing a bean does not enable an optional protocol or change the installed routes; those decisions belong to [build-time configuration](./configuration).

## Public packages and internals {#api-boundary}

Application APIs use the `io.quarkiverse.authorization.server` namespace, organized by domains such as `client`, `authorization`, `token`, `settings`, `grant.<grant-type>` and `oidc`. Related contexts, models, builders and request base classes belong to these public packages. The three JDBC implementations are in `jdbc`.

The `runtime.*` and `deployment.*` packages are internal, including their public classes and methods. Use the SPIs listed here; default implementation names explain assembly and do not make every default an application contract. Internal refactoring should preserve public packages and signatures. Changes to public APIs require a separate impact review.

## Replacement and composition {#composition}

Single-value defaults use `@DefaultBean`: an application bean of the expected type and qualifiers replaces the fallback. Two unresolved application candidates cause a build-time ambiguity; ordinary `@Priority` does not choose between them.

Ordered hooks use `@All @Default List<SPI>`. ArC supplies beans in descending `@Priority` order; an unannotated bean has priority zero, and equal priorities do not define a stable order. A bean with only a custom qualifier such as `@Identifier` is not in that default list. `@Named` may still carry `@Default`, so it is not a way to keep a helper out of composition.

The lists retain CDI-managed instances and their interceptors. Mandatory protocol checks remain in the services; application validators add policy after those checks. Evidence: [AuthorizationServerProcessor], [OAuth2TokenGeneratorProducer] and [AuthorizationServerCdiCompositionTest].

## Repositories and credentials {#repositories}

Each row is a single-value replacement. The default repositories are process-local and lose their state on restart.

<div class="reference-table" role="region" aria-label="Repository and credential SPI table; scroll horizontally if needed" tabindex="0">

| SPI | Default | Application responsibility |
| --- | --- | --- |
| [RegisteredClientRepository] | `InMemoryRegisteredClientRepository`, initialized from config | Replace client lookup/persistence; a custom bean does not import or merge configured clients |
| [OAuth2AuthorizationService] | `InMemoryOAuth2AuthorizationService` | Authorizations, tokens and pending protocol state; JDBC implementation available |
| [OAuth2AuthorizationConsentService] | `InMemoryOAuth2AuthorizationConsentService` | Persistent user/client consent; JDBC implementation available |
| [ClientSecretVerifier] | `BcryptClientSecretVerifier` | Verify Basic/POST client secrets; this is not the user-password verifier |
| [ClientSecretEncoder] | `BcryptClientSecretEncoder` | Encode generated registration secrets where hashing applies |
| [AuthorizationServerKeySource] | `ConfiguredAuthorizationServerKeySource` | Supply signing material and active key; see [signing](./signing) |
| [DPoPReplayStore] | `InMemoryDPoPReplayStore` | Atomic replay claims; distributed storage is application-owned |

</div>

For JDBC producers, schema and transaction boundaries, use [Storage and signing keys](/guide/storage-and-keys). Returning different bean objects does not itself isolate shared database rows.

## Single-value protocol policies {#single-components}

<div class="reference-table" role="region" aria-label="Protocol SPI table; scroll horizontally if needed" tabindex="0">

| SPI | Default | Purpose |
| --- | --- | --- |
| [AuthorizationConsentPolicy] | `DefaultAuthorizationConsentPolicy` | Decide whether validated Code authorization needs consent |
| [AuthorizationCodeGenerator] | `DefaultAuthorizationCodeGenerator` | Generate authorization codes |
| [DeviceConsentPolicy] | `DefaultDeviceConsentPolicy` | Decide device consent requirements |
| [DeviceCodeGenerator], [UserCodeGenerator] | `OAuth2DeviceCodeGenerator`, `OAuth2UserCodeGenerator` | Generate device/user codes |
| [OAuth2AuthorizationConsentPage] | `DefaultConsentPage` | Render browser consent and submit the required protocol fields |
| [OAuth2DeviceVerificationPage] | `DefaultDeviceVerificationPage` | Render device input, confirmation and results |
| [OidcUserInfoMapper] | `DefaultOidcUserInfoMapper` | Select UserInfo claims |
| [OidcSessionManager] | `FormAuthenticationSessionManager`, when Form integration is available | OIDC browser-session identity, authentication time and termination |
| [OidcLogoutRequestValidator] | `OidcLogoutValidator` | Validate logout policy; explicitly retain default redirect checks when extending it |
| [ClientRegistrationScopeValidator] | `DefaultClientRegistrationScopeValidator` | Scope admission shared by the default OAuth/OIDC registration validators |
| [OAuth2ClientRegistrationRequestValidator] | `DefaultOAuth2ClientRegistrationRequestValidator` | OAuth registration scope/business policy |
| [OidcClientRegistrationRequestValidator] | `OidcClientRegistrationValidator` | OIDC registration URI/scope/business policy |
| [RegisteredClientMapper] | `DefaultRegisteredClientMapper` | Map OIDC registration to a `RegisteredClient` |
| [ClientRegistrationMapper] | `RegisteredClientOidcClientRegistrationConverter` | Map registered clients to OIDC registration/read responses |
| [OAuth2TokenGenerator]`<OAuth2Token>` | `DelegatingOAuth2TokenGenerator` | Entire signing/JWT, opaque access-token and refresh-token generation chain |

</div>

Replacing a complete generator or registration mapper also makes its assembly the application's responsibility. The default generator composes `JwtGenerator`, `OAuth2AccessTokenGenerator` and `OAuth2RefreshTokenGenerator`; defining an arbitrary extra generator bean does not append it to this chain.

Pages are Vert.x HTTP integration SPIs, not Qute/REST resources. Replacing one does not provide a JSON interaction API or a user database. Consent and device-confirmation page replacements can coexist with built-in login.

To change the built-in login URL, keep `default-login-page-enabled=true` and configure the Quarkus Form page locations. To supply your own login implementation, disable that switch and provide the page, authentication mechanism selection and desired Form settings. Disabling it removes the extension's browser mechanism selection and three additional defaults, not just the HTML. There is no separate login-page SPI; `BrowserLoginSecurityConfiguration` is an internal integration component. See [Browser login](./configuration#browser-login) and [Identity and access](/guide/identity-and-access).

## Ordered validators and customizers {#ordered-components}

| SPI | Invocation / default behavior |
| --- | --- |
| [AuthorizationRequestValidator] | Initial authorization and PAR validation; fallback is a no-op after fixed protocol checks |
| [ClientCredentialsRequestValidator] | Validated Client Credentials request; no-op fallback |
| [AuthorizationConsentCustomizer] | Before Code consent persistence; can change decision and authorities |
| [DeviceConsentCustomizer] | Approved device consent before persistence; cannot override explicit rejection |
| [OAuth2TokenCustomizer]`<JwtEncodingContext>` | JWT headers/claims; no-op application fallback |
| [OAuth2TokenCustomizer]`<OAuth2TokenClaimsContext>` | Opaque access-token claims; empty application list by default |
| [AuthorizationServerMetadataCustomizer] | OAuth discovery metadata; no-op fallback |
| [OidcProviderMetadataCustomizer] | OIDC discovery metadata; no-op fallback |
| [RegistrationClientSettingsCustomizer] | `ClientSettings.Builder` for both dynamic-registration contracts; no-op fallback |
| [RegistrationTokenSettingsCustomizer] | `TokenSettings.Builder` for both dynamic-registration contracts; no-op fallback |

The two token-customizer types are distinct CDI injection targets. Built-in Token Exchange claims run before application token customizers. The default OIDC `RegisteredClientMapper` applies both registration-settings lists; a replacement mapper must preserve any composition it wants.

For example, add user roles only to an access-token JWT, without changing ID Token claims:

```java
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import io.quarkiverse.authorization.server.token.JwtEncodingContext;
import io.quarkiverse.authorization.server.token.OAuth2TokenCustomizer;
import io.quarkiverse.authorization.server.token.OAuth2TokenType;

@Singleton
public class TokenClaims {
    @Produces
    @Singleton
    OAuth2TokenCustomizer<JwtEncodingContext> accessTokenRoles() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claim("groups", context.getPrincipal().getRoles());
            }
        };
    }
}
```

`getPrincipal()` is a Quarkus `SecurityIdentity`. Code/Refresh may use a historical authorization identity; these are not guaranteed to be the user's latest roles. Scope is a client's allowed delegation range, not a substitute for user authorization. Resource APIs still enforce their own roles/permissions.

### Retaining registration validation {#registration-policy}

For scope-only customization, provide a `ClientRegistrationScopeValidator` bean. Both default OAuth and OIDC request validators use it while retaining their URI checks. The supplied scope set is immutable and empty when no scopes are requested. The default implementation rejects nonempty scopes; static-client scope configuration does not replace this policy.

```java
import java.util.Set;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import io.quarkiverse.authorization.server.client.registration.ClientRegistrationScopeValidator;
import io.quarkiverse.authorization.server.model.OAuth2AuthenticationException;
import io.quarkiverse.authorization.server.model.OAuth2ErrorCodes;

@Singleton
public class RegistrationPolicy {
    @Produces
    @Singleton
    ClientRegistrationScopeValidator registrationScopes() {
        return scopes -> {
            if (!Set.of("openid", "profile").containsAll(scopes)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
        };
    }
}
```

The full `OAuth2ClientRegistrationRequestValidator` / `OidcClientRegistrationRequestValidator` beans remain replacement hooks for advanced policies requiring the complete request context. A replacement owns scope admission and the replaceable OIDC URI checks. To append business restrictions to the OIDC defaults, inject `ClientRegistrationScopeValidator scopes` into the producer and return `new OidcClientRegistrationValidator(scopes).andThen(...)`. These hooks are not automatically accumulated validator lists: the default rejection of nonempty scopes does not run alongside an application's scope allowance.

Fixed metadata checks, supported authentication methods and reserved scopes cannot be bypassed by replacing either business validator. Scope policies run on the protocol worker with an active CDI request context and may inject request-scoped dependencies. Rejection occurs before client storage or initial-token consumption. See [ClientRegistrationScopeValidatorTest] and [OidcRegistrationCdiCompositionTest].

## User identity and request context {#identity-context}

User authentication is Quarkus Security's responsibility. Supply `IdentityProvider<UsernamePasswordAuthenticationRequest>` for password authentication. Form's subsequent requests also need `IdentityProvider<TrustedAuthenticationRequest>` to reload the cookie's user; use providers from a suitable Quarkus identity extension or implement both against the same user store. These are two authentication request types, not two separate user databases. Password grant alone does not need the Form reload provider.

Synchronous protocol services execute on workers with a CDI request context. [ProtocolExecutor] bridges this for the handlers that use it, including access to `CurrentVertxRequest`; the authorize handler uses `VertxContextSupport.executeBlocking` directly. Request-time validators and token customizers may use `@RequestScoped` dependencies. Do not read a request in bean constructors or producers, and do not assume page-rendering callbacks or arbitrary application routes are worker tasks.

This execution boundary **does not start a transaction**. See [storage boundaries](./protocol-support#storage).

## Tenants and custom grants {#tenants-grants}

Multiple issuers require one [AuthorizationServerTenant] bean per configured tenant, selected by `@Identifier(tenantId)`. Each bundle supplies its client repository, authorization service, consent service and key source. The registry requires exactly one matching bean and distinct repository/service instances across tenants; it cannot verify isolation within a shared database. There is no fallback to another tenant's state. Shared protocol policies are not automatically tenant-specific. See [AuthorizationServerTenantRegistry] and [multi-issuer configuration](./configuration#multiple-issuers).

[TokenGrantHandler] is the advanced token-endpoint dispatch SPI: `getGrantType()` identifies the grant at startup; `handle(RoutingContext)` returns `Uni<TokenIssuanceResult>`. Duplicate grant identifiers fail startup, so adding another handler for a built-in grant is not a priority-based override. A custom handler owns parsing, client/grant policy, execution boundaries and results. Merely adding a grant name to client config does not implement it or update every discovery/registration capability check.

These are application integration points, not a promise that all internal classes are stable public API in the current version.

[AuthorizationCodeGenerator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/authorizationcode/AuthorizationCodeGenerator.java
[AuthorizationConsentCustomizer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/authorizationcode/AuthorizationConsentCustomizer.java
[AuthorizationConsentPolicy]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/authorizationcode/AuthorizationConsentPolicy.java
[AuthorizationRequestValidator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/authorizationcode/AuthorizationRequestValidator.java
[AuthorizationServerCdiCompositionTest]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/AuthorizationServerCdiCompositionTest.java
[AuthorizationServerKeySource]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/token/AuthorizationServerKeySource.java
[AuthorizationServerMetadataCustomizer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/metadata/AuthorizationServerMetadataCustomizer.java
[AuthorizationServerProcessor]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/AuthorizationServerProcessor.java
[AuthorizationServerTenant]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/tenant/AuthorizationServerTenant.java
[AuthorizationServerTenantRegistry]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/tenant/AuthorizationServerTenantRegistry.java
[ClientCredentialsRequestValidator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/clientcredentials/ClientCredentialsRequestValidator.java
[ClientRegistrationMapper]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/oidc/registration/ClientRegistrationMapper.java
[ClientSecretEncoder]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/ClientSecretEncoder.java
[ClientSecretVerifier]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/ClientSecretVerifier.java
[DPoPReplayStore]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/dpop/DPoPReplayStore.java
[DeviceCodeGenerator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/devicecode/DeviceCodeGenerator.java
[DeviceConsentCustomizer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/devicecode/DeviceConsentCustomizer.java
[DeviceConsentPolicy]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/devicecode/DeviceConsentPolicy.java
[OAuth2AuthorizationConsentPage]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/authorizationcode/OAuth2AuthorizationConsentPage.java
[OAuth2AuthorizationConsentService]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/authorization/OAuth2AuthorizationConsentService.java
[OAuth2AuthorizationService]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/authorization/OAuth2AuthorizationService.java
[OAuth2ClientRegistrationRequestValidator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/registration/OAuth2ClientRegistrationRequestValidator.java
[OAuth2DeviceVerificationPage]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/devicecode/OAuth2DeviceVerificationPage.java
[OAuth2TokenCustomizer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/token/OAuth2TokenCustomizer.java
[OAuth2TokenGenerator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/token/OAuth2TokenGenerator.java
[OAuth2TokenGeneratorProducer]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/OAuth2TokenGeneratorProducer.java
[OidcClientRegistrationRequestValidator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/oidc/registration/OidcClientRegistrationRequestValidator.java
[OidcLogoutRequestValidator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/oidc/logout/OidcLogoutRequestValidator.java
[OidcProviderMetadataCustomizer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/oidc/OidcProviderMetadataCustomizer.java
[OidcRegistrationCdiCompositionTest]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/OidcRegistrationCdiCompositionTest.java
[OidcSessionManager]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/oidc/session/OidcSessionManager.java
[OidcUserInfoMapper]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/oidc/userinfo/OidcUserInfoMapper.java
[ProtocolExecutor]: https://github.com/flynndi/quarkus-authorization-server/blob/f8edc23584e7857f70189e8c975129bd14cc8d82/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/web/ProtocolExecutor.java
[RegisteredClientMapper]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/oidc/registration/RegisteredClientMapper.java
[RegisteredClientRepository]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/RegisteredClientRepository.java
[RegistrationClientSettingsCustomizer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/registration/RegistrationClientSettingsCustomizer.java
[RegistrationTokenSettingsCustomizer]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/registration/RegistrationTokenSettingsCustomizer.java
[TokenGrantHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/web/TokenGrantHandler.java
[UserCodeGenerator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/devicecode/UserCodeGenerator.java

[ClientRegistrationScopeValidator]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/client/registration/ClientRegistrationScopeValidator.java
[ClientRegistrationScopeValidatorTest]: https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/ClientRegistrationScopeValidatorTest.java

---
layout: page
sidebar: false
pageClass: architecture-page
---

<script setup>
import ArchitecturePage from '../.vitepress/theme/components/ArchitecturePage.vue'
</script>

<ArchitecturePage>

# Architecture

The extension runs inside a Quarkus application. It provides OAuth protocol handling and token issuance; your application supplies users, clients, persistence and access rules. The [quickstart](./getting-started) runs the authorization server and resource API in separate processes. They can also share a process, as some repository examples do; their protocol responsibilities remain distinct.

## Three boundaries

| Component | Responsibility | Credentials it uses |
| --- | --- | --- |
| Browser / OAuth client | Start authorization, handle the callback, exchange the code, call an API | A public client uses PKCE; a confidential client also authenticates itself |
| Authorization server | Authenticate users and clients, obtain consent, issue and track tokens | User login, Form cookie and OAuth client authentication are separate concerns |
| Resource server | Validate an access token and authorize the requested operation | Bearer token, or DPoP when explicitly configured for that flow |

For the Vue example, the password is submitted to the authorization server's page. Vue receives the authorization code at its registered callback; its API requests carry an access token. A Form cookie is not an API credential.

## Public API and internal packages {#api-boundary}

Java packages below share the `io.quarkiverse.authorization.server` prefix. The `runtime` Gradle module contains both public APIs and internal implementations; the module name does not define the API boundary.

| Package | Application-facing types and responsibilities |
| --- | --- |
| `client` | `RegisteredClient`, `RegisteredClientRepository` and client-secret contracts |
| `authorization` | `OAuth2AuthorizationService`, `OAuth2AuthorizationConsentService` and their stored models |
| `token` | `OAuth2TokenGenerator`, `OAuth2TokenCustomizer`, token contexts and `AuthorizationServerKeySource` |
| `grant.authorizationcode`, `grant.devicecode` and other `grant.*` packages | Typed requests, contexts, validators, consent policies and page SPIs |
| `web` | `TokenGrantHandler`, the CDI HTTP adapter contract for a custom token grant |
| `jdbc` | The three JDBC implementations that an application can provide through CDI |

`runtime.*` holds internal protocol services, handlers and default assembly. `deployment.*` holds internal build steps. A `public` Java declaration in either package does not make that class an application extension point. For example, applications implement `web.TokenGrantHandler`; the built-in `runtime.grant.authorizationcode.web.AuthorizationCodeGrantHandler` invokes `AuthorizationCodeExchange` through the internal `runtime.web.ProtocolExecutor`.

The diagram keeps 11 components and links each to source paths and line ranges at one fixed Git commit. Its package labels distinguish public contracts from internal execution. Select a component to inspect its source links; **About** shows the source revision and downloadable JSON. See [CDI extension points](/reference/extensions#api-boundary) for supported customization contracts.

## Build-time wiring

[`AuthorizationServerProcessor`](https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/AuthorizationServerProcessor.java) installs Vert.x routes, HTTP security integration and CDI components during Quarkus augmentation. Endpoint paths and optional features determine what is installed. Changing build-time or build-and-run-time-fixed configuration requires a new build.

Runtime configuration supplies values such as the issuer, configured clients, signing keys and DPoP settings. “Runtime” does not mean that the extension reloads those values on every request.

## Runtime request handling

At the token endpoint:

1. Quarkus HTTP Security and the extension's client authentication components establish the client `SecurityIdentity`.
2. `OAuth2TokenEndpointHandler` selects a `TokenGrantHandler` by `grant_type`.
3. The grant's parser creates a typed request. Its HTTP adapter invokes the synchronous protocol service through `ProtocolExecutor` on a worker with an active request context.
4. The service checks the registered client and authorization, then uses the shared `OAuth2TokenGenerator` to issue tokens.
5. The HTTP layer serializes the result or protocol error.

Authorization and device verification also have browser interactions before token exchange. Those pages and redirects do not belong to the resource API.

The extension uses Vert.x handlers for its protocol routes. The examples use Quarkus REST for their own small resource APIs; consumers do not need REST resources to install OAuth endpoints.

Sources: [`TokenGrantHandler`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/web/TokenGrantHandler.java), [`ProtocolExecutor`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/web/ProtocolExecutor.java), [`OAuth2TokenGeneratorProducer`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/OAuth2TokenGeneratorProducer.java).

## Three stores

| Contract | What it stores |
| --- | --- |
| `RegisteredClientRepository` | Client authentication methods, grants, redirect URIs, scopes and token settings |
| `OAuth2AuthorizationService` | Authorization state, issued tokens and their metadata |
| `OAuth2AuthorizationConsentService` | A user's recorded consent for a registered client |

The defaults are in-memory. A CDI repository replaces the corresponding default; a custom client repository is not automatically populated from `clients.*`. See [storage and signing keys](./storage-and-keys).

## Application extension points

Use Quarkus Config for external values and CDI for behavior. Applications can provide user `IdentityProvider` implementations, repositories, validators, consent policies/customizers, token customizers, key sources and page beans. There is no additional configuration DSL.

Single-value contracts replace their default implementation. Composable contracts such as token customizers run as an ordered list. Prefer the smallest relevant extension point: adding one claim does not require replacing token generation.

Continue with [Authorization Code + PKCE](./authorization-code), [Client Credentials](./client-credentials), or the [configuration reference](/reference/). See [Protocol support](/reference/protocol-support) for implementation boundaries.

</ArchitecturePage>

# CDI 扩展点

外部值使用 Quarkus Config，行为使用 CDI，没有额外配置 DSL。提供 Bean 不会启用可选协议或改变已安装路由；这些由[构建期配置](./configuration)决定。

## 公开包与内部实现 {#api-boundary}

应用 API 以 `io.quarkiverse.authorization.server` 为根，按 `client`、`authorization`、`token`、`settings`、`grant.<授权类型>`、`oidc` 等领域组织。接口关联的上下文、模型、Builder 和请求基类位于同一套公开包；三个 JDBC 实现集中在 `jdbc`。

`runtime.*` 与 `deployment.*` 是内部实现包，即使类或方法声明为 `public`，也不作为应用扩展契约。应用使用本页列出的 SPI；默认实现名称用于解释装配，不表示所有默认实现都应被应用直接依赖。内部重构应保持公开包与签名稳定，公开 API 的变更需单独评估。

## 替换与组合 {#composition}

单值默认实现使用 `@DefaultBean`：应用提供匹配类型和 qualifier 的 Bean 后替换兜底实现。两个无法消歧的应用候选会导致构建失败，普通 `@Priority` 不会自动二选一。

有序钩子使用 `@All @Default List<SPI>`。ArC 按 `@Priority` 从大到小提供 Bean；未声明时为零，同优先级不保证稳定顺序。仅有 `@Identifier` 等自定义 qualifier 的 Bean 不进入默认列表。`@Named` 仍可能带 `@Default`，不能靠它将辅助 Bean 排除出组合。

列表保留 CDI 托管实例及其拦截器。固定协议检查仍在 service 中执行，应用 validator 在这些检查之后追加策略。证据见 [AuthorizationServerProcessor]、[OAuth2TokenGeneratorProducer] 和 [AuthorizationServerCdiCompositionTest]。

## 仓储与凭据 {#repositories}

每一行都是单值替换。默认仓储位于当前进程内，重启丢失状态。

<div class="reference-table" role="region" aria-label="仓储与凭据 SPI 表，可按需横向滚动" tabindex="0">

| SPI | 默认实现 | 应用职责 |
| --- | --- | --- |
| [RegisteredClientRepository] | `InMemoryRegisteredClientRepository`，由配置初始化 | 替换 client 查询/持久化；自定义 Bean 不导入或合并配置 client |
| [OAuth2AuthorizationService] | `InMemoryOAuth2AuthorizationService` | Authorization、token 和待处理协议状态；提供 JDBC 实现 |
| [OAuth2AuthorizationConsentService] | `InMemoryOAuth2AuthorizationConsentService` | 持久化用户/client consent；提供 JDBC 实现 |
| [ClientSecretVerifier] | `BcryptClientSecretVerifier` | 校验 Basic/POST client secret，不是用户密码验证器 |
| [ClientSecretEncoder] | `BcryptClientSecretEncoder` | 对适用哈希的动态注册 secret 编码 |
| [AuthorizationServerKeySource] | `ConfiguredAuthorizationServerKeySource` | 提供签名材料和活动 key；见[签名密钥](./signing) |
| [DPoPReplayStore] | `InMemoryDPoPReplayStore` | 原子认领 replay 记录；分布式存储由应用提供 |

</div>

JDBC producer、schema 和事务边界见[存储与签名密钥](/zh/guide/storage-and-keys)。返回不同 Bean 对象本身不隔离共享数据库中的记录。

## 单值协议策略 {#single-components}

<div class="reference-table" role="region" aria-label="协议 SPI 表，可按需横向滚动" tabindex="0">

| SPI | 默认实现 | 用途 |
| --- | --- | --- |
| [AuthorizationConsentPolicy] | `DefaultAuthorizationConsentPolicy` | 判断已验证 Code 授权是否需要 consent |
| [AuthorizationCodeGenerator] | `DefaultAuthorizationCodeGenerator` | 生成 authorization code |
| [DeviceConsentPolicy] | `DefaultDeviceConsentPolicy` | 决定设备 consent 要求 |
| [DeviceCodeGenerator]、[UserCodeGenerator] | `OAuth2DeviceCodeGenerator`、`OAuth2UserCodeGenerator` | 生成 device/user code |
| [OAuth2AuthorizationConsentPage] | `DefaultConsentPage` | 渲染浏览器 consent 并提交所需协议字段 |
| [OAuth2DeviceVerificationPage] | `DefaultDeviceVerificationPage` | 渲染设备输入、确认和结果 |
| [OidcUserInfoMapper] | `DefaultOidcUserInfoMapper` | 选择 UserInfo claims |
| [OidcSessionManager] | Form 集成可用时的 `FormAuthenticationSessionManager` | OIDC 浏览器会话身份、认证时间与退出 |
| [OidcLogoutRequestValidator] | `OidcLogoutValidator` | Logout 策略校验；扩展时显式保留默认 redirect 检查 |
| [ClientRegistrationScopeValidator] | `DefaultClientRegistrationScopeValidator` | OAuth/OIDC 默认注册校验共享的 scope 准入策略 |
| [OAuth2ClientRegistrationRequestValidator] | `DefaultOAuth2ClientRegistrationRequestValidator` | OAuth 注册 scope/业务策略 |
| [OidcClientRegistrationRequestValidator] | `OidcClientRegistrationValidator` | OIDC 注册 URI/scope/业务策略 |
| [RegisteredClientMapper] | `DefaultRegisteredClientMapper` | 将 OIDC 注册映射为 `RegisteredClient` |
| [ClientRegistrationMapper] | `RegisteredClientOidcClientRegistrationConverter` | 将注册 client 映射为 OIDC 注册/读取响应 |
| [OAuth2TokenGenerator]`<OAuth2Token>` | `DelegatingOAuth2TokenGenerator` | 完整签名/JWT、opaque access token 和 refresh token 生成链 |

</div>

替换整个 generator 或 registration mapper 后，应用也负责其装配。默认 generator 组合 `JwtGenerator`、`OAuth2AccessTokenGenerator` 和 `OAuth2RefreshTokenGenerator`；随意新增一个 generator Bean 不会将它追加到这条链。

页面是 Vert.x HTTP 集成 SPI，不是 Qute/REST resource。替换页面不自动提供 JSON 交互 API 或用户库。自定义 consent 和设备确认页可继续搭配内置登录。

仅修改内置登录 URL 时，保持 `default-login-page-enabled=true` 并设置 Quarkus Form 页面路径即可。自行实现登录时则关闭该开关，接管页面、认证机制选择与所需的 Form 属性；关闭后移除的是扩展的浏览器机制选择与三个额外缺省值，不只是 HTML。没有独立 login-page SPI，`BrowserLoginSecurityConfiguration` 是内部集成组件。见[浏览器登录](./configuration#browser-login)与[身份与访问控制](/zh/guide/identity-and-access)。

## 有序 validator 与 customizer {#ordered-components}

| SPI | 调用时机 / 默认行为 |
| --- | --- |
| [AuthorizationRequestValidator] | 初始授权和 PAR 校验；固定协议检查后，默认应用策略为空操作 |
| [ClientCredentialsRequestValidator] | 已校验的 Client Credentials 请求；默认空操作 |
| [AuthorizationConsentCustomizer] | Code consent 持久化前，可修改决定和 authorities |
| [DeviceConsentCustomizer] | 已批准的 device consent 持久化前；不能覆盖显式拒绝 |
| [OAuth2TokenCustomizer]`<JwtEncodingContext>` | JWT header/claims；默认应用策略为空操作 |
| [OAuth2TokenCustomizer]`<OAuth2TokenClaimsContext>` | Opaque access-token claims；默认应用列表为空 |
| [AuthorizationServerMetadataCustomizer] | OAuth discovery 元数据；默认空操作 |
| [OidcProviderMetadataCustomizer] | OIDC discovery 元数据；默认空操作 |
| [RegistrationClientSettingsCustomizer] | 两种动态注册的 `ClientSettings.Builder`；默认空操作 |
| [RegistrationTokenSettingsCustomizer] | 两种动态注册的 `TokenSettings.Builder`；默认空操作 |

两种 token customizer 是不同的 CDI 注入目标。内置 Token Exchange claims 先于应用 token customizer 执行。默认 OIDC `RegisteredClientMapper` 使用两组 registration settings 列表；替换 mapper 后，需自行保留所需组合。

例如，仅向 access-token JWT 添加用户角色，不改变 ID Token claims：

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

`getPrincipal()` 是 Quarkus `SecurityIdentity`。Code/Refresh 可能使用历史授权身份，不保证是用户最新角色。Scope 是客户端允许委托的范围，不替代用户授权。资源 API 仍需执行自己的角色/权限判断。

### 保留注册校验 {#registration-policy}

只修改动态注册允许的 scope 时，提供一个 `ClientRegistrationScopeValidator` Bean。OAuth 与 OIDC 的默认 request validator 共用它，默认 URI 校验继续执行。传入的 scope 集合不可变；未请求 scope 时为空集合。默认实现拒绝非空 scope，静态客户端的 scope 配置不会替代这项策略。

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

完整的 `OAuth2ClientRegistrationRequestValidator` / `OidcClientRegistrationRequestValidator` 仍是替换型入口，适合需要整个请求上下文的高级策略；替换后，应用负责组合所需的 scope 校验以及可替换的 OIDC URI 校验。若要在默认 OIDC 规则之后追加业务限制，可向 producer 注入 `ClientRegistrationScopeValidator scopes`，返回 `new OidcClientRegistrationValidator(scopes).andThen(...)`。它们不是自动累加的 validator 列表，也不会把“默认拒绝非空 scope”和“应用允许某些 scope”同时执行。

固定 metadata 检查、认证方式支持范围和保留 scope 不会被业务 validator 替换绕过。Scope 策略在协议 worker 和 CDI request context 中执行，可注入请求作用域依赖；失败时尚未保存客户端或消费 initial token。见 [ClientRegistrationScopeValidatorTest] 和 [OidcRegistrationCdiCompositionTest]。

## 用户身份与请求上下文 {#identity-context}

用户认证属于 Quarkus Security。密码认证提供 `IdentityProvider<UsernamePasswordAuthenticationRequest>`。Form 后续请求还需要 `IdentityProvider<TrustedAuthenticationRequest>` 重新加载 Cookie 中的用户；可使用合适的 Quarkus 身份扩展提供的 provider，也可让两个 provider 共用同一用户库。这是两种认证请求，不是两套用户库。单独使用 Password grant 不需要 Form reload provider。

同步协议 service 在具有 CDI request context 的 worker 上运行。[ProtocolExecutor] 为使用它的 handler 提供该边界，包括 `CurrentVertxRequest` 访问；authorize handler 直接使用 `VertxContextSupport.executeBlocking`。请求期间的 validator 和 token customizer 可使用 `@RequestScoped` 依赖。不要在 Bean 构造器或 producer 中读取请求，也不要假定页面渲染回调或任意应用路由都在 worker 上。

此执行边界**不开启事务**。见[存储边界](./protocol-support#storage)。

## Tenant 与自定义 grant {#tenants-grants}

Multiple issuers 要求每个配置 tenant 提供一个 [AuthorizationServerTenant] Bean，通过 `@Identifier(tenantId)` 选择。每个 bundle 提供 client repository、authorization service、consent service 和 key source。Registry 要求恰好一个匹配 Bean，且不同 tenant 的仓储/service 实例不同；它无法验证共享数据库内部的隔离。不会回退到其他 tenant 的状态，共享协议策略也不会自动变成逐 tenant 策略。见 [AuthorizationServerTenantRegistry] 和[多 issuer 配置](./configuration#multiple-issuers)。

[TokenGrantHandler] 是高级 token 端点分发 SPI：`getGrantType()` 在启动时标识 grant，`handle(RoutingContext)` 返回 `Uni<TokenIssuanceResult>`。重复 grant 标识会导致启动失败，为内置 grant 添加另一个 handler 不是基于 priority 的覆盖机制。自定义 handler 负责解析、client/grant 策略、执行边界和结果。仅在 client 配置中增加 grant 名称不会实现它，也不会更新全部 discovery/registration 能力检查。

这些是应用集成入口，不意味着当前版本的所有内部类都是稳定公共 API。

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

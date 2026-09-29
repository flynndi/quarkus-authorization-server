---
layout: page
sidebar: false
pageClass: architecture-page
---

<script setup>
import ArchitecturePage from '../../.vitepress/theme/components/ArchitecturePage.vue'
</script>

<ArchitecturePage>

# 架构 {#architecture}

扩展运行在 Quarkus 应用内部，提供 OAuth 协议处理与 token 签发；应用提供用户、客户端、持久化和访问规则。[快速开始](./getting-started)将授权服务器与资源 API 运行在不同进程中。也可以像部分仓库示例一样合并部署；各自的协议职责仍然独立。

## 三个边界 {#three-boundaries}

| 组件 | 职责 | 使用的凭据 |
| --- | --- | --- |
| 浏览器 / OAuth 客户端 | 发起授权、处理 callback、兑换 code、调用 API | public client 使用 PKCE；confidential client 还需认证客户端自身 |
| 授权服务器 | 认证用户和客户端、获取 consent、签发并记录 token | 用户登录、Form Cookie 与 OAuth 客户端认证各有职责 |
| 资源服务器 | 验证 access token，判断是否允许当前操作 | Bearer token；相应流程显式配置后也可使用 DPoP |

在 Vue 示例里，用户在授权服务器页面提交密码。Vue 在注册的 callback 收到 code，调用资源 API 时携带 access token。Form Cookie 不能充当资源 API 的凭据。

## 公开 API 与内部包 {#api-boundary}

以下 Java 包均以 `io.quarkiverse.authorization.server` 为前缀。`runtime` Gradle 模块同时包含公开 API 与内部实现，模块名不等于 API 边界。

| 包 | 应用可使用的类型与职责 |
| --- | --- |
| `client` | `RegisteredClient`、`RegisteredClientRepository` 及客户端 secret 接口 |
| `authorization` | `OAuth2AuthorizationService`、`OAuth2AuthorizationConsentService` 及其存储模型 |
| `token` | `OAuth2TokenGenerator`、`OAuth2TokenCustomizer`、token 上下文和 `AuthorizationServerKeySource` |
| `grant.authorizationcode`、`grant.devicecode` 等 `grant.*` 包 | 类型化请求、上下文、validator、consent policy 和页面 SPI |
| `web` | `TokenGrantHandler`，通过 CDI 扩展 token grant 的 HTTP 适配契约 |
| `jdbc` | 应用可以通过 CDI 装配的三个 JDBC 实现 |

`runtime.*` 保存内部协议服务、handler 和默认装配；`deployment.*` 保存内部 build steps。这两个包中的类即使声明为 `public`，也不属于应用扩展契约。例如应用实现 `web.TokenGrantHandler`；内置的 `runtime.grant.authorizationcode.web.AuthorizationCodeGrantHandler` 则通过内部 `runtime.web.ProtocolExecutor` 调用 `AuthorizationCodeExchange`。

架构图保留 11 个组件，每个组件的源码路径与行号均固定到同一个 Git 提交。图中的包标签区分公开契约与内部执行；选中组件可查看源码链接，**关于**菜单提供源码版本与 JSON 下载。可定制的契约见 [CDI 扩展点](/zh/reference/extensions#api-boundary)。

## 构建期装配 {#build-time-wiring}

[`AuthorizationServerProcessor`](https://github.com/flynndi/quarkus-authorization-server/blob/main/deployment/src/main/java/io/quarkiverse/authorization/server/deployment/AuthorizationServerProcessor.java) 在 Quarkus augmentation 阶段安装 Vert.x 路由、HTTP Security 集成和 CDI 组件。端点路径与可选功能决定安装内容；修改构建期或构建后固定的配置需要重新构建。

运行期配置提供 issuer、配置客户端、签名密钥和 DPoP 参数等值。“运行期”不表示扩展会在每个请求中重新加载这些值。

## 运行期请求处理 {#runtime-request-handling}

Token Endpoint 的处理过程：

1. Quarkus HTTP Security 和扩展的客户端认证组件建立客户端 `SecurityIdentity`。
2. `OAuth2TokenEndpointHandler` 按 `grant_type` 选择 `TokenGrantHandler`。
3. grant 的 parser 生成类型化请求；HTTP adapter 通过 `ProtocolExecutor` 在 worker 和有效 request context 中调用同步协议服务。
4. 服务检查客户端与授权记录，再使用共享 `OAuth2TokenGenerator` 签发 token。
5. HTTP 层输出结果或协议错误。

Authorization 与 Device Verification 在兑换 token 前还有浏览器交互。这些页面与重定向不属于资源 API。

扩展的协议路由使用 Vert.x handler；示例中的业务资源 API 使用 Quarkus REST。安装 OAuth 端点不要求应用编写 REST Resource。

源码：[`TokenGrantHandler`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/web/TokenGrantHandler.java)、[`ProtocolExecutor`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/web/ProtocolExecutor.java)、[`OAuth2TokenGeneratorProducer`](https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/config/OAuth2TokenGeneratorProducer.java)。

## 三类存储 {#three-stores}

| 接口 | 保存内容 |
| --- | --- |
| `RegisteredClientRepository` | 客户端认证方式、grant、redirect URI、scope 与 token 设置 |
| `OAuth2AuthorizationService` | 授权状态、已签发 token 与相关 metadata |
| `OAuth2AuthorizationConsentService` | 用户对指定客户端的历史 consent |

默认使用内存实现。应用提供 CDI 仓储会替换对应默认实现；自定义客户端仓储不会自动导入 `clients.*`。见[存储与签名密钥](./storage-and-keys)。

## 应用扩展点 {#application-extension-points}

外部值用 Quarkus Config，行为用 CDI。应用可以提供用户 `IdentityProvider`、仓储、validator、consent policy/customizer、token customizer、key source 和页面 Bean，没有额外的统一配置 DSL。

单值接口替换默认实现；token customizer 等组合接口按顺序执行。优先使用职责最小的扩展点：增加一个 claim 不需要替换整个 token 生成器。

继续阅读 [Authorization Code + PKCE](./authorization-code)、[Client Credentials](./client-credentials)，或[配置参考](/zh/reference/)。实现边界见[协议能力与边界](/zh/reference/protocol-support)。

</ArchitecturePage>

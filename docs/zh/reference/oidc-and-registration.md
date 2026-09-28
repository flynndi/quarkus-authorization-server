# OIDC 与注册

以下假定使用默认端点和 HTTP root。[服务端配置](./configuration)列出所需构建期开关；[OAuth 端点](./endpoints)描述 Code、token、PAR 和设备请求。

## OIDC 端点 {#oidc-endpoints}

启用 `quarkus.authorization-server.oidc.enabled=true`。Client 还需登记对应 `openid` scope、redirect 和 grant。

<div class="reference-table" role="region" aria-label="OIDC 端点表，可按需横向滚动" tabindex="0">

| 方法与默认路径 | 输入与认证 | 结果 |
| --- | --- | --- |
| `GET /.well-known/openid-configuration` | 公开；无 body | `200` JSON provider 元数据；多 issuer 模式下此路径接在 issuer 路径后 |
| `GET /userinfo`、`POST /userinfo` | `Authorization: Bearer …` 或 `Authorization: DPoP …`；绑定 token 还需 `DPoP` proof 请求头 | `200` JSON claims |
| `GET /connect/logout` | Query；必填 `id_token_hint` | `302` 到已验证的 post-logout URI 或 `/` |
| `POST /connect/logout` | 表单；与 GET 相同参数 | 相同退出结果 |

</div>

### UserInfo {#userinfo}

UserInfo 只从 `Authorization` 请求头读取 token，不读取 query 或表单 `access_token`。POST 不定义 JSON/表单请求负载。服务端要求有效的已存储 access token、`openid` scope，以及包含 ID Token 的对应 authorization。DPoP 绑定 token 不能当作 Bearer 使用；proof 必须匹配 key、请求方法/URI 和 access-token hash（`ath`）。

```bash
curl --header 'Authorization: Bearer REPLACE_WITH_OPENID_ACCESS_TOKEN' \
  'http://localhost:8080/userinfo'
```

[DefaultOidcUserInfoMapper] 按授予的 scope，从已存储 ID Token 中选择 claims：`sub` 加适用的 `profile`、`email`、`phone`、`address`、`groups` 和 `perms` claims。它不重新加载用户，也不补出 ID Token 中不存在的 claims。应用可替换 `OidcUserInfoMapper`。响应为 JSON，未实现签名/加密 UserInfo 响应。

典型错误为 `401 invalid_token`、`403 insufficient_scope` 和 `400 invalid_request`；认证/授权错误包含相应 challenge。内部映射错误使用 `500 server_error`。见 [OidcUserInfoAuthenticationMechanism]、[OidcUserInfoEndpointHandler] 和 [OidcUserInfoService]。

### RP-Initiated Logout {#logout}

`id_token_hint` 必填。可选单值参数为 `client_id`、`post_logout_redirect_uri` 和 `state`。Service 验证 hint、client、用户/会话上下文及已注册 redirect；接受 post-logout redirect 时返回 `state`。匿名浏览器可提交有效 hint，但不会凭空产生可退出的已认证会话。

默认 `OidcSessionManager` 集成 Quarkus Form。Logout 结束匹配的浏览器会话，不撤销已签发 access/refresh token 或已有 consent。缺失/非法参数返回 JSON `400`；POST 表单媒体类型错误返回 `415`。未实现无 hint 退出、front-channel logout 或 back-channel logout。见 [OidcLogoutRequestParser]、[OidcLogoutService] 和 [OidcLogoutEndpointHandler]。

## 注册端点 {#registration-endpoints}

这是两套独立接口。两者都接受 JSON（`application/json` 或 `application/*+json`），创建成功返回 `201`，拒绝不支持的 metadata，不接受表单 POST。

<div class="reference-table" role="region" aria-label="注册端点表，可按需横向滚动" tabindex="0">

| 端点 | 开关与凭据 | 结果 / 管理能力 |
| --- | --- | --- |
| `POST /oauth2/register` | `client-registration.enabled=true`；Bearer initial access token。匿名请求还需 `client-registration.open-registration-allowed=true`。 | Client metadata 及适用时的 secret；无 registration access token 或管理 GET/PUT/DELETE |
| `POST /connect/register` | `oidc.enabled=true` 和 `oidc.client-registration.enabled=true`；必须使用 Bearer initial access token | Metadata、可选 client secret、`registration_access_token`、`registration_client_uri` |
| `GET /connect/register?client_id=…` | 相同 OIDC 开关；与该 client 绑定的 Bearer registration access token | `200` metadata，不含 client secret；无 PUT/DELETE |

</div>

同时启用时，两种注册的路径必须不同。开放 OAuth 注册不会开启匿名 OIDC 注册。调用方若向开放端点提交了非法凭据，仍然失败，不会退回匿名注册。

### Initial 与 registration access token {#registration-tokens}

Initial token 必须是有效、本地存储的 Bearer access token，scope 集合**恰好**为 `client.create`。受保护注册成功后，会使该初始 authorization 的 access token 和存在的 refresh token 失效。同时包含 `client.create` 和其他 scope 的 token 会被拒绝。Initial token 由应用提供；注册功能没有匿名获取引导 token 的端点。

OIDC 另行返回 scope 恰好为 `client.read` 的 registration access token，绑定新 client 用于读取配置。生成该 token 不会将 Client Credentials grant 加入新 client。不能将保留 scope `client.create` / `client.read` 注册为新 client 的 scope。见 [RegistrationAccessTokens] 和 [OidcClientRegistrationService]。

### 接受的 metadata {#registration-metadata}

| 接口 | 接受的请求字段 |
| --- | --- |
| 两者共有 | `client_name`、`token_endpoint_auth_method`、`grant_types`、`response_types`、`redirect_uris`、`scope` |
| 仅 OIDC | `post_logout_redirect_uris`、`jwks_uri`、`tls_client_auth_subject_dn`、`token_endpoint_auth_signing_alg`、`id_token_signed_response_alg` |

`scope` 是空格分隔字符串；URI、grant 和 response 列表为 JSON 数组。Client ID、secret 和注册凭据由服务端生成，不作为请求 metadata 接受；未知字段不会静默保存。

OAuth 注册只接受 `client_secret_basic`、`client_secret_post` 和 `none`，默认 `client_secret_basic`。未提供 grant 时默认为 `authorization_code`。Response type 只支持 `code`。Code client 需要 redirect URI。此注册接口将 public client 的 grant 限制为 Code、Device 和 Refresh。

OIDC 注册接受七种[客户端认证方式](./endpoints#client-authentication)，但有对应 metadata 约束：`private_key_jwt` 和 `self_signed_tls_client_auth` 需要 `jwks_uri`，`tls_client_auth` 需要 subject DN，assertion 签名算法必须匹配认证方式。默认行为包括 Basic 认证、grant/response metadata 推导出的 Code、ID Token 的 `RS256`、私钥 assertion 的 `RS256` 和 secret assertion 的 `HS256`。不适用 Code 默认值时应明确提交 grant/response 数组。

两种注册默认启用 PKCE 和 consent。**默认 scope 策略拒绝非空请求 scope。** 应用可提供一个 `ClientRegistrationScopeValidator` Bean，为两种默认注册 validator 指定允许的 scope，同时保留默认 URI 校验；静态客户端配置不会设置动态注册策略。见 [CDI 参考](./extensions#registration-policy)。固定 metadata/capability 检查仍会执行。

需要 secret 的注册仅在创建时返回生成的明文 secret。默认 encoder 存储 bcrypt 值，`client_secret_jwt` 除外，它需要可用的共享密钥材料。不能通过配置读取取回 secret。实现见 [OAuth2ClientRegistrationRequestParser]、[OAuth2ClientRegistrationService]、[OidcClientRegistrationMetadataValidator] 和 [OidcClientRegistrationRegisteredClientConverter]。

### 示例与错误 {#registration-example}

以下受保护 OAuth 示例特意不请求 scope；提供有效 initial token 后即可通过默认 scope validator：

```bash
curl --header 'Authorization: Bearer REPLACE_WITH_INITIAL_ACCESS_TOKEN' \
  --header 'Content-Type: application/json' \
  --data '{"client_name":"Machine demo","token_endpoint_auth_method":"client_secret_basic","grant_types":["client_credentials"],"response_types":[]}' \
  'http://localhost:8080/oauth2/register'
```

开放注册部署可省略 Authorization 请求头；client 持久化和 scope 策略仍然生效。

典型状态为 `400 invalid_request`、`invalid_client_metadata`、`invalid_redirect_uri` 或 `invalid_scope`；`401 invalid_token`；`403 insufficient_scope`；媒体类型错误为 `415`；内部错误为 `500 server_error`。缺少所需 scope 与携带额外 scope 是不同错误。默认 client 保存、registration token 保存和 initial token 失效是分开的写操作：`500` 不保证没有任何数据落库。见[协议边界](./protocol-support#storage)。

## 源码与既有覆盖 {#evidence}

源码链接固定到核对的提交。既有覆盖包括 [OidcUserInfoEndpointTest]、[OidcLogoutEndpointTest]、[OAuthClientRegistrationEndpointTest]、[OAuthClientRegistrationOpenTest] 和 [OidcClientRegistrationPolicyTest]。这些测试区分受保护/开放注册并验证失败行为；本次纯文档修改未重新执行它们。

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

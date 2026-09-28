# OAuth 端点

本文描述实际安装的 HTTP 接口。以下路径假定使用默认端点、单 issuer 且 `quarkus.http.root-path=/`。自定义路径后应使用发现文档；开关、HTTP root 和多 issuer 发现地址见[服务端配置](./configuration)。路由由 [AuthorizationServerRecorder] 安装。

## 端点索引 {#endpoint-index}

“表单”指 `application/x-www-form-urlencoded`；“客户端”指[客户端认证](#client-authentication)，不是登录用户。可选功能只有启用对应构建期开关后才安装。

<div class="reference-table" role="region" aria-label="端点表，可按需横向滚动" tabindex="0">

| 方法与默认路径 | 输入与认证 | 成功结果 |
| --- | --- | --- |
| `GET /.well-known/oauth-authorization-server` | 公开；无 body | `200` JSON 服务端元数据 |
| `GET /oauth2/jwks` | 公开；无 body | `200` 公钥 JWK Set |
| `GET /oauth2/authorize` | Query；先做协议校验，再挑战用户登录 | 登录、consent HTML 或带 code 的 `302` |
| `POST /oauth2/authorize` | 表单；初始 OIDC/PAR 请求或已认证用户提交 consent | 登录续接、consent HTML 或带 code 的 `302` |
| `POST /oauth2/token` | 表单；客户端 | `200` JSON token 响应 |
| `POST /oauth2/introspect` | 表单；客户端 | `200` 含 `active` 的 JSON |
| `POST /oauth2/revoke` | 表单；客户端 | `200`，空 body |
| `POST /oauth2/device_authorization` | 表单；客户端 | `200` JSON device/user code |
| `GET /oauth2/device_verification` | Query；要求用户登录 | 输入 code 或确认 HTML |
| `POST /oauth2/device_verification` | 表单；已认证用户 | 确认或完成 HTML |
| `POST /oauth2/par` | 表单；客户端；`pushed-authorization-requests-enabled=true` | `201` JSON 引用及有效期 |

</div>

OIDC discovery、UserInfo、logout 和两种注册端点见 [OIDC 与注册](./oidc-and-registration)。可选默认登录页使用 Quarkus Form 配置，不是固定 OAuth 端点。

## 客户端认证 {#client-authentication}

Token、introspection、revocation、device authorization 和 PAR 使用 [OAuth2ClientAuthenticationMechanism]。在 `RegisteredClient` 上配置认证方式：

| 方式 | 请求凭据 |
| --- | --- |
| `client_secret_basic` | HTTP Basic 请求头 |
| `client_secret_post` | 表单 `client_id` 和 `client_secret` |
| `private_key_jwt`、`client_secret_jwt` | 表单 `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` 和 `client_assertion` |
| `tls_client_auth`、`self_signed_tls_client_auth` | TLS 客户端证书和表单 `client_id` |
| `none` | 表单 `client_id`；标识 public client，不证明持有 secret |

Introspection、revocation、Client Credentials、Password 和 Token Exchange 需要客户端凭据，public `none` 标识不足以调用。

每次请求只使用一种认证方式。混合凭据和重复认证参数会被拒绝。Public 标识不意味着可使用所有 grant：各 service 仍检查客户端、PKCE 和 token 绑定要求。认证失败通常返回 `401 invalid_client`；认证请求格式错误可返回 `400 invalid_request`。Secret 表示、assertion 算法、JWK URL 和 TLS 要求见[注册客户端](./clients)。

## 授权与 consent {#authorization}

初始请求使用 `response_type=code`、必填 `client_id`、可选空格分隔 `scope` 和不透明的客户端 `state`。应提交已注册的 `redirect_uri`；仅非 OIDC 请求且只登记一个 URI 时允许省略并推断。OIDC 请求必须提交它。PKCE 使用 `code_challenge` 和 `code_challenge_method=S256`；public Code client 必须使用 PKCE。OIDC 请求的 `scope` 包含 `openid`，还可提供 `nonce` 和 `prompt`。可选 `dpop_jkt` 将 Code 流程预绑定到 DPoP key thumbprint，必须为 43 字符的 base64url 值，并匹配换码时的 proof。

常规浏览器请求使用 GET。初始表单 POST 只识别带 `response_type` 和 `openid` 的 OIDC 请求，或 PAR `request_uri`，不是普通 OAuth GET 的通用替代方式。已校验的初始 POST 如果需要登录，会先通过 `303` 转为 query URL，让 Quarkus Form 在认证后恢复。该区别由 [AuthorizationRequestParser] 和 [OAuth2AuthorizationEndpointHandler] 定义。

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

这段只展示请求，不代表已有浏览器登录会话。需先配置 `web` client、redirect、scope 和 OIDC。[Code 指南](/zh/guide/authorization-code)提供可运行的浏览器流程。

Client、response type、redirect、scope 和 PKCE 在登录前校验。只有服务端已验证过的 URI 才会收到错误重定向，否则返回 JSON `400`。典型错误包括 `invalid_request`、`invalid_scope`、`unauthorized_client` 和 `unsupported_response_type`。OIDC `prompt=none` 在无法静默完成时返回 `login_required` 或 `consent_required`；`none` 不能与其他 prompt 组合。这不等于实现了完整重认证或账号选择流程。

Consent 是向同一端点提交的另一种表单 POST，不带 `response_type` 或 `request_uri`：

| 参数 | 约定 |
| --- | --- |
| `client_id`、`state` | 必填单值，来自待确认上下文。这里的 `state` 是内部待处理请求状态，不是客户端原始 state。 |
| `scope` | 可选重复字段，每个值对应一个选中 scope；不同于初始请求的空格分隔字符串。 |
| `consent_action` | 可选单值 `approve` 或 `deny`；省略表示 `approve`。 |

提交必须匹配已认证用户和待处理请求。`AuthorizationConsentCustomizer` 可在持久化前修改决定和 authorities。最终拒绝返回 `access_denied` 并消费待处理请求；已有 consent 会保留，除非 authorities 被清空。清空全部 authorities 会删除已有 consent，与决定无关。见 [ConsentSubmissionParser]、[AuthorizationConsentContext] 和 [CDI 参考](./extensions#ordered-components)。

## Token grant {#token-grants}

每次 token 请求需要一个非空 `grant_type`、配置的客户端认证及已登记的对应 grant。单值参数拒绝重复。Grant adapter 由 [OAuth2TokenEndpointHandler] 选择。

<div class="reference-table" role="region" aria-label="Grant 参数表，可按需横向滚动" tabindex="0">

| `grant_type` | 必填 grant 参数 | 可选参数与约束 |
| --- | --- | --- |
| `authorization_code` | `code` | 原请求提供过 `redirect_uri` 时须一致；PKCE `code_verifier` 须匹配 challenge。Code 必须属于该 client 且仍有效。 |
| `refresh_token` | `refresh_token` | `scope` 可缩小原范围，省略沿用原范围。绑定的 refresh 需要相同 DPoP key 的 proof。 |
| `client_credentials` | 无 | 空格分隔 `scope`，不得超出已注册范围；省略得到空 scope 集合。不发 refresh token。 |
| `password` | `username`、`password` | 空格分隔 `scope`。使用应用的 Quarkus 密码身份提供者；不支持 DPoP。 |
| `urn:ietf:params:oauth:grant-type:device_code` | `device_code` | 设备须已批准、仍有效且绑定当前 client。 |
| `urn:ietf:params:oauth:grant-type:token-exchange` | `subject_token`、`subject_token_type` | 成对 `actor_token` / `actor_token_type`；`requested_token_type`、`scope`、可重复 `resource` 和 `audience`。 |

</div>

Token Exchange 接受 token type URN `urn:ietf:params:oauth:token-type:access_token` 和 `urn:ietf:params:oauth:token-type:jwt`，请求输出类型默认为 `access_token`。输入须对应有效的本地 authorization。Subject 需要资源所有者身份；Client Credentials token 可以作为 actor，不能作为用户 subject。委托检查使用 `may_act` / `act`。这不是交换任意外部 JWT 的端点。见 [TokenExchangeRequestParser] 和 [TokenExchangeGrant]。

```bash
curl --user 'machine:REPLACE_WITH_CLIENT_SECRET' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'scope=message.read' \
  'http://localhost:8080/oauth2/token'
```

响应包含 `access_token`、`token_type`、有效期和非空时的 `scope`，以及适用时的 `refresh_token`、OIDC `id_token` 或 Token Exchange `issued_token_type`。DPoP 使用 `DPoP` proof 请求头，受支持的绑定流程返回 `token_type=DPoP`；见 [DPoP](./dpop) 和 [refresh 边界](./protocol-support#tokens)。

典型错误：`invalid_request`、`invalid_client`、`unauthorized_client`、`invalid_grant`、`invalid_scope`、`unsupported_grant_type`、`unsupported_token_type`、`invalid_dpop_proof`。设备轮询还可能返回 `authorization_pending`、`access_denied` 或 `expired_token`。表单媒体类型错误返回 `415`；客户端认证后的协议错误使用 `400`。认证可早于媒体类型检查失败。不能假定所有错误都有 JSON body，或所有内部错误都使用 `500`。

## Introspection 与 revocation {#token-management}

两者都接收必填 `token` 和可选 `token_type_hint`，均为表单单值。当前 hint 不限制仓储查询范围。

```bash
curl --user 'resource-client:REPLACE_WITH_CLIENT_SECRET' \
  --data-urlencode 'token=REPLACE_WITH_ACCESS_TOKEN' \
  'http://localhost:8080/oauth2/introspect'

curl --user 'machine:REPLACE_WITH_CLIENT_SECRET' \
  --data-urlencode 'token=REPLACE_WITH_OWN_TOKEN' \
  --data-urlencode 'token_type_hint=access_token' \
  'http://localhost:8080/oauth2/revoke'
```

[OAuth2TokenIntrospectionAuthenticationProvider] 对未知或失效 token 返回 `{"active":false}`。有效响应使用存储的 claims 和元数据。当前 provider **不**将 introspection 限制为签发 client，也不实施资源专属 audience 策略；内置入口条件是客户端认证。

[OAuth2TokenRevocationAuthenticationProvider] 对未知 token 按撤销成功处理，但已知 token 必须属于当前认证 client。不匹配返回 `invalid_client`。撤销改变存储的 authorization 状态；离线校验 JWT 的外部资源服务器不会自动感知。缺失/重复参数返回 `400 invalid_request`；认证后的表单媒体类型不匹配返回 `415`。

## Device 流程 {#device-flow}

Device authorization 接收可选空格分隔 `scope`。Public client 提交 `client_id`，confidential client 正常认证。JSON 包含 `device_code`、`user_code`、`verification_uri`、`verification_uri_complete` 和 `expires_in`。当前响应省略 `interval`，没有轮询限速或 `slow_down` 响应；客户端不能假定服务端会限制轮询速率。

用户打开 `verification_uri` 输入 code，或打开带 `user_code` 的 `verification_uri_complete`。GET 和包含 `user_code` 的表单 POST 可准备确认，不能批准设备。确认 POST 必须包含单值 `client_id`、`user_code`、内部 `state`、`approved=true` 或 `false`，以及可选重复 `scope`。State 绑定用户、client 和设备。与 Code consent 的决定钩子不同，显式拒绝不能被 `DeviceConsentCustomizer` 改为批准。

默认页面在本地报告完成；设备通过轮询 `/oauth2/token` 获取 token。非法或不匹配的提交返回错误页，通常为 `400`；意外验证错误使用 `500`。见 [OAuth2DeviceVerificationEndpointHandler] 和 [DeviceConsentSubmissionParser]。

## Pushed Authorization Requests {#par}

PAR 接收初始授权参数的表单数据和客户端认证，不负责资源所有者登录。`request`（JAR）和嵌套 `request_uri` 会被拒绝。

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

`201` 响应返回 `request_uri` 和 `expires_in=300`。Redirect、scope、state 和 prompt 只由已存储的请求决定，外层 query 不能覆盖。服务端检查引用的 client、有效期和当前客户端策略。登录和静默错误响应保留引用；创建待确认 consent 后消费引用，并通过内部 consent state 续接，直接签发 code 也会消费引用。普通授权仍可使用，没有逐 client 的强制 PAR 设置。

典型错误包括 `invalid_request`、`invalid_scope` 和 `invalid_client`。PAR 错误返回 JSON，不做浏览器重定向；不支持的方法返回 `405`，媒体类型错误为 `415`，内部失败为 `500`。浏览器阶段的引用错误遵守 authorize 的已验证 redirect 规则。实现见 [PushedAuthorizationEndpointHandler] 和 [PushedAuthorizationRequests]。

## 源码与既有覆盖 {#evidence}

本页源码链接固定到核对的提交。既有端点覆盖包括 [AuthorizationEndpointTest]、[TokenEndpointTest]、[OAuth2DeviceAuthorizationEndpointTest] 和 [PushedAuthorizationEndpointTest]。这些链接用于定位实现证据；构建文档不等于重新执行了这些测试。

[AuthorizationConsentContext]: https://github.com/flynndi/quarkus-authorization-server/blob/main/runtime/src/main/java/io/quarkiverse/authorization/server/grant/authorizationcode/AuthorizationConsentContext.java
[AuthorizationEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/AuthorizationEndpointTest.java
[AuthorizationRequestParser]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/AuthorizationRequestParser.java
[AuthorizationServerRecorder]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/AuthorizationServerRecorder.java
[ConsentSubmissionParser]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/ConsentSubmissionParser.java
[DeviceConsentSubmissionParser]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/devicecode/web/DeviceConsentSubmissionParser.java
[OAuth2AuthorizationEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/OAuth2AuthorizationEndpointHandler.java
[OAuth2ClientAuthenticationMechanism]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/client/web/OAuth2ClientAuthenticationMechanism.java
[OAuth2DeviceAuthorizationEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/OAuth2DeviceAuthorizationEndpointTest.java
[OAuth2DeviceVerificationEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/devicecode/web/OAuth2DeviceVerificationEndpointHandler.java
[OAuth2TokenEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/web/OAuth2TokenEndpointHandler.java
[OAuth2TokenIntrospectionAuthenticationProvider]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/introspection/authentication/OAuth2TokenIntrospectionAuthenticationProvider.java
[OAuth2TokenRevocationAuthenticationProvider]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/revocation/authentication/OAuth2TokenRevocationAuthenticationProvider.java
[PushedAuthorizationEndpointHandler]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/web/PushedAuthorizationEndpointHandler.java
[PushedAuthorizationEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/PushedAuthorizationEndpointTest.java
[PushedAuthorizationRequests]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/authorizationcode/authorization/PushedAuthorizationRequests.java
[TokenEndpointTest]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/deployment/src/test/java/io/quarkiverse/authorization/server/deployment/TokenEndpointTest.java
[TokenExchangeGrant]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/tokenexchange/TokenExchangeGrant.java
[TokenExchangeRequestParser]: https://github.com/flynndi/quarkus-authorization-server/blob/1d1c6d530e0cc7fabf88e7e541316abfcb00abcb/runtime/src/main/java/io/quarkiverse/authorization/server/runtime/grant/tokenexchange/web/TokenExchangeRequestParser.java

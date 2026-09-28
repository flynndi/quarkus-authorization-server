---
title: OAuth 请求构造器
description: 为已有的授权模式构造授权 URL 或表单 POST。本页面不会发送请求。
---

<script setup>
import RequestTool from '../../.vitepress/theme/playground/RequestTool.vue'
</script>

# OAuth 请求构造器

为已有的授权模式构造授权 URL 或表单 POST。本页面不会发送请求。

<RequestTool />

## 执行示例前

- 将示例端点与 client ID 替换为实际注册信息。工具使用完整端点 URL，可以直接填写自定义路径与 issuer 前缀。支持 HTTP(S) 回调 URI，请原样复制注册的 URI。
- 授权 URL 用于浏览器顶层导航；curl 命令用于兼容 POSIX 的终端，提交 `application/x-www-form-urlencoded` 表单。构造成功不代表已验证服务器、客户端注册或回调处理。
- 工具提供 `none` 和 `client_secret_basic`。服务器支持的其他[客户端认证方式](/zh/reference/endpoints#client-authentication)需另行配置。OAuth 的 Basic 认证要求先分别对 client ID 和 secret 做表单编码，再做 Basic 编码。输出中的 client ID 已编码，请使用表单编码后的 secret 替换占位符。
- 在本地替换 code、token 和密码占位符。Code 兑换前须校验回调中的 `state`；使用 `openid` 时还须保留并验证 OIDC `nonce`。PKCE 不替代这些检查。
- 刷新示例使用 confidential client 的非绑定 token。本工具不生成 DPoP proof，也不演示 public client 的刷新流程。

设备轮询遵循 [RFC 8628 §3.5](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5)：使用服务端返回的 interval，缺省时为 5 秒。当前服务器不返回 `interval`，也不强制轮询限速；实际行为见[端点参考](/zh/reference/endpoints#device-flow)。

输入与生成值只保留在页面内存中，不上传、不持久化，也不写入页面 URL。使用构造器无需输入 secret。需要发送真实请求时，前往 [在线 Playground](/zh/playground/)。

---
title: JWT 解码
description: 在本地查看 JWT 的 Header 与 Payload。本工具不验证签名，也不判断 token 是否有效。
---

<script setup>
import JwtTool from '../../.vitepress/theme/playground/JwtTool.vue'
</script>

# JWT 解码

在本地查看 JWT 的 Header 与 Payload。本工具不验证签名，也不判断 token 是否有效。

<JwtTool />

## 如何理解输出

解码器读取三段式紧凑 JWT，包括未签名 token。它检查 base64url 和 JSON 编码，但不信任任何声明，也不会下载密钥。五段式加密 JWE 和不透明 token 无法在此解码。

解码得到的 `exp`、`iss`、`aud` 或角色均未经验证。资源服务器仍需验证 token 并执行自己的权限规则，见 [Token 与资源服务器](/zh/guide/tokens-and-resources)。JWT 序列化规则见 [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)。

样例包含虚构签名，不能用于认证请求。输入只保留在当前标签页的内存中，不上传、不写入分享 URL，也不写入浏览器存储。完成后清空或离开页面即可。

---
title: PKCE 生成与核验
description: 生成 verifier 与对应的 S256 challenge，或核对现有的一组参数。所有计算均在当前标签页内完成。
---

<script setup>
import PkceTool from '../../.vitepress/theme/playground/PkceTool.vue'
</script>

# PKCE 生成与核验

生成 verifier 与对应的 S256 challenge，或核对现有的一组参数。所有计算均在当前标签页内完成。

<PkceTool />

## 如何使用

1. 授权请求携带 `code_challenge` 和 `code_challenge_method=S256`。
2. 客户端保留 `code_verifier` 直到回调，用它兑换授权码。
3. 每次授权都生成新的 verifier。RFC 样例是公开测试数据。

计算规则为 `BASE64URL(SHA256(ASCII(code_verifier)))`，不带 `=` 填充。内置测试向量来自 [RFC 7636 附录 B](https://www.rfc-editor.org/rfc/rfc7636.html#appendix-B)。

输入只保存在当前页面的内存中，不上传、不写入分享 URL，也不写入浏览器存储。离开或刷新前按需复制。

继续使用[请求构造器](./requests)，或阅读 [Authorization Code + PKCE](/zh/guide/authorization-code)。

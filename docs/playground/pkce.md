---
title: PKCE generator
description: Generate a verifier and its S256 challenge, or check an existing pair. All calculations stay in this tab.
---

<script setup>
import PkceTool from '../.vitepress/theme/playground/PkceTool.vue'
</script>

# PKCE generator

Generate a verifier and its S256 challenge, or check an existing pair. All calculations stay in this tab.

<PkceTool />

## Use the pair

1. Send `code_challenge` and `code_challenge_method=S256` in the authorization request.
2. Keep `code_verifier` in the client until the callback. Send it when exchanging the authorization code.
3. Generate a fresh verifier for every authorization request. The RFC example is public test data.

The calculation is `BASE64URL(SHA256(ASCII(code_verifier)))`, without `=` padding. The built-in test vector is from [RFC 7636 Appendix B](https://www.rfc-editor.org/rfc/rfc7636.html#appendix-B).

Inputs exist only in this page's memory: no upload, URL sharing or browser storage. Copy only what you need before leaving or reloading the page.

Continue with the [request builder](./requests) or read [Authorization Code + PKCE](/guide/authorization-code).

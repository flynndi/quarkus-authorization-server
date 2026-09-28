---
title: JWT decoder
description: Inspect a JWT header and payload locally. This tool does not verify signatures or decide whether a token is valid.
---

<script setup>
import JwtTool from '../.vitepress/theme/playground/JwtTool.vue'
</script>

# JWT decoder

Inspect a JWT header and payload locally. This tool does not verify signatures or decide whether a token is valid.

<JwtTool />

## What the output means

The decoder reads three-part compact JWTs, including unsecured tokens. It checks base64url and JSON encoding, but does not trust any claim or fetch a key. Five-part encrypted JWE tokens and opaque tokens cannot be decoded here.

A decoded `exp`, `iss`, `aud` or role is unverified input. Resource servers must validate the token and apply their own access policy; see [tokens and resource servers](/guide/tokens-and-resources). JWT serialization is defined in [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html).

The example contains a dummy signature and cannot authenticate a request. Your input stays in this tab's memory: no upload, URL sharing or browser storage. Clear it or leave the page when finished.

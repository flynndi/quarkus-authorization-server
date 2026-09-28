---
title: OAuth request builder
description: Assemble an authorization URL or a form POST for an existing grant. Nothing is sent from this page.
---

<script setup>
import RequestTool from '../.vitepress/theme/playground/RequestTool.vue'
</script>

# OAuth request builder

Assemble an authorization URL or a form POST for an existing grant. Nothing is sent from this page.

<RequestTool />

## Before running an example

- Replace the example endpoints and client ID with your registration. This builder uses exact endpoint URLs, so custom paths and issuer prefixes can be entered directly. HTTP(S) redirect URIs are supported; copy the registered URI exactly.
- Authorization URLs are for top-level browser navigation. The curl commands are for a POSIX-compatible terminal and send `application/x-www-form-urlencoded` bodies. Building an example does not verify the server, client registration or your redirect handler.
- The builder covers `none` and `client_secret_basic`. The server supports other [client authentication methods](/reference/endpoints#client-authentication); configure those separately. For Basic authentication, OAuth requires form-encoding the client ID and secret before Basic encoding. The client ID is already encoded in the output; replace the secret placeholder with a form-encoded secret.
- Replace the code, token and password placeholders locally. For Code, validate callback `state` before exchange; retain and verify OIDC `nonce` when using `openid`. PKCE does not replace these checks.
- The refresh example uses an unbound confidential-client token. This tool does not construct DPoP proofs, and does not demonstrate a public-client refresh flow.

Device polling follows [RFC 8628 §3.5](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5): use the server's interval, or 5 seconds if absent. The current server omits `interval`; it does not enforce polling throttles. See the [endpoint reference](/reference/endpoints#device-flow) for the actual behavior.

Inputs and generated values remain in page memory; they are not uploaded, persisted or put in the page URL. No secret is needed to use the builder. To send real requests, open the [live Playground](/playground/).

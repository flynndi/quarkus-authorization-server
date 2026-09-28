<script setup lang="ts">
import { ref, watch } from 'vue'
import { decodeJwt, jwtExample } from './oauth-tools.mjs'
import { useToolText } from './useToolText'
import ToolOutput from './ToolOutput.vue'

const { t, errorText } = useToolText()
const input = ref('')
const result = ref<ReturnType<typeof decodeJwt> | null>(null)
const error = ref('')
watch(input, () => { result.value = null; error.value = '' }, { flush: 'sync' })
function decode() {
  result.value = null; error.value = ''
  try { result.value = decodeJwt(input.value) }
  catch (cause) { error.value = errorText(cause) }
}
function sample() { input.value = jwtExample; decode() }
</script>

<template>
  <div class="pg-tool">
    <div class="pg-toolbar">
      <span class="pg-local">{{ t('BROWSER ONLY', '仅在浏览器内运行') }}</span>
      <button type="button" class="pg-text-button" @click="input = ''; result = null; error = ''">{{ t('Clear', '清空') }}</button>
    </div>
    <form @submit.prevent="decode">
      <label class="pg-field" for="jwt-input">{{ t('Encoded JWT', 'JWT 原文') }}
        <textarea id="jwt-input" v-model="input" rows="6" spellcheck="false" autocomplete="off" autocapitalize="off" aria-describedby="jwt-help" />
      </label>
      <p id="jwt-help" class="pg-help">{{ t('Paste a three-part JWT. Header and payload are decoded locally; encrypted JWE tokens are not supported.', '粘贴三段式 JWT，在本地解码 Header 与 Payload；不支持加密的 JWE。') }}</p>
      <div class="pg-actions">
        <button class="pg-primary" type="submit">{{ t('Decode token', '解码 Token') }}</button>
        <button class="pg-secondary" type="button" @click="sample">{{ t('Load example', '载入样例') }}</button>
      </div>
    </form>
    <p class="pg-notice">{{ t('Decoding does not verify the signature, issuer, audience or expiry. The example has a dummy signature. Never use this output as proof of identity.', '解码不验证签名、issuer、audience 或有效期。样例使用虚构签名，不能将解码结果作为身份凭据。') }}</p>
    <p v-if="error" class="pg-error" role="alert">{{ error }}</p>
    <div v-if="result" class="pg-results">
      <span class="pg-unverified">{{ t('DECODED · NOT VERIFIED', '已解码 · 未验证') }}</span>
      <ToolOutput label="Header" :value="JSON.stringify(result.header, null, 2)" />
      <ToolOutput label="Payload" :value="JSON.stringify(result.payload, null, 2)" />
    </div>
  </div>
</template>

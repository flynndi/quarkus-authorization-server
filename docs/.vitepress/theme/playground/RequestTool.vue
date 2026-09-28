<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { buildRequests, grants, ToolError } from './oauth-tools.mjs'
import { useToolText } from './useToolText'
import ToolOutput from './ToolOutput.vue'

const { t, errorText } = useToolText()
const defaults = () => ({
  grant: 'authorization_code', clientId: 'demo-client', auth: 'none', scope: 'message.read',
  authorizationEndpoint: 'https://as.example/oauth2/authorize', tokenEndpoint: 'https://as.example/oauth2/token',
  deviceEndpoint: 'https://as.example/oauth2/device_authorization', redirectUri: 'http://localhost:5173/callback'
})
const form = reactive(defaults())
const result = ref<Awaited<ReturnType<typeof buildRequests>>>([])
const error = ref('')
const busy = ref(false)
const publicAllowed = computed(() => ['authorization_code', 'device_code'].includes(form.grant))
watch(() => form.grant, () => { form.auth = publicAllowed.value ? 'none' : 'client_secret_basic' }, { flush: 'sync' })
watch(form, () => { result.value = []; error.value = '' }, { flush: 'sync' })
const grantNames: Record<string, string> = {
  authorization_code: 'Authorization Code + PKCE', client_credentials: 'Client Credentials',
  refresh_token: 'Refresh Token', device_code: 'Device Authorization', password: 'Password', token_exchange: 'Token Exchange'
}
const labels = computed<Record<string, string>>(() => ({
  verifier: t('Keep for the code exchange', '保留到 Code 兑换时使用'),
  authorization: t('Authorization URL · browser navigation', '授权 URL · 浏览器导航'),
  token: t('Token request · terminal', 'Token 请求 · 在终端执行'),
  device: t('Request device codes · terminal', '申请设备码 · 在终端执行'),
  poll: t('Poll for tokens · terminal', '轮询 Token · 在终端执行')
}))
type InputField = { key: Exclude<keyof ReturnType<typeof defaults>, 'grant' | 'auth'>; label: string }
const fields = computed(() => {
  const items: InputField[] = []
  if (form.grant === 'authorization_code') items.push({ key: 'authorizationEndpoint', label: t('Authorization endpoint', '授权端点') })
  if (form.grant === 'device_code') items.push({ key: 'deviceEndpoint', label: t('Device authorization endpoint', '设备授权端点') })
  items.push({ key: 'tokenEndpoint', label: t('Token endpoint', 'Token 端点') }, { key: 'clientId', label: 'client_id' })
  if (form.grant === 'authorization_code') items.push({ key: 'redirectUri', label: 'redirect_uri' })
  items.push({ key: 'scope', label: t('scope (space-separated, optional)', 'scope（空格分隔，可选）') })
  return items
})
async function build() {
  busy.value = true; error.value = ''; result.value = []
  try { result.value = await buildRequests({ ...form }) }
  catch (cause) {
    const field = cause instanceof ToolError ? fields.value.find(field => field.key === cause.field) : undefined
    error.value = (field ? field.label + ': ' : '') + errorText(cause)
  } finally { busy.value = false }
}
function reset() { Object.assign(form, defaults()); result.value = []; error.value = '' }
</script>

<template>
  <div class="pg-tool">
    <div class="pg-toolbar">
      <span class="pg-local">{{ t('BUILD ONLY · NO REQUESTS SENT', '仅构造示例 · 不发送请求') }}</span>
      <button class="pg-text-button" type="button" :disabled="busy" @click="reset">{{ t('Reset', '重置') }}</button>
    </div>
    <form @submit.prevent="build">
      <fieldset :disabled="busy">
        <div class="pg-field-grid">
          <label class="pg-field" for="request-grant">{{ t('Grant', '授权模式') }}
            <select id="request-grant" v-model="form.grant">
              <option v-for="grant in grants" :key="grant" :value="grant">{{ grantNames[grant] }}</option>
            </select>
          </label>
          <label class="pg-field" for="request-auth">{{ t('Client authentication', '客户端认证') }}
            <select id="request-auth" v-model="form.auth">
              <option v-if="publicAllowed" value="none">{{ t('none (public client)', 'none（公开客户端）') }}</option>
              <option value="client_secret_basic">client_secret_basic</option>
            </select>
          </label>
        </div>
        <label v-for="field in fields" :key="field.key" class="pg-field" :for="'request-' + field.key">{{ field.label }}
          <input :id="'request-' + field.key" v-model="form[field.key]" type="text" spellcheck="false" autocomplete="off" autocapitalize="off" :maxlength="2048" />
        </label>
        <p class="pg-help">{{ t('Use your registered client and exact endpoint paths. as.example is a placeholder. Secrets, codes and tokens remain placeholders in the output.', '请使用已注册的客户端和实际端点路径。as.example 是占位地址；输出中的 secret、code 和 token 均使用占位符。') }}</p>
        <p v-if="form.grant === 'authorization_code'" class="pg-notice">{{ t('Each build creates a fresh verifier and state, plus a nonce when scope includes openid. Keep this pair together and validate state at the callback.', '每次构造都会生成新的 verifier 和 state；scope 包含 openid 时还会生成 nonce。请保留同一组参数，并在回调时校验 state。') }}</p>
        <p v-if="form.grant === 'refresh_token'" class="pg-notice">{{ t('This is an unbound confidential-client refresh example. Omit scope to retain the original scopes, or narrow them. Public Authorization Code clients need DPoP to receive and use refresh tokens in this server.', '此处演示 confidential client 的非绑定刷新。省略 scope 保留原范围，或填写其子集。当前服务器的 public Authorization Code client 需要 DPoP 才能获得和使用 refresh token。') }}</p>
        <p v-if="form.grant === 'device_code'" class="pg-notice">{{ t('Have the user approve the device before expecting tokens. Poll no faster than the returned interval, or every 5 seconds when it is absent; handle pending and expiry responses.', '用户确认设备后才能获得 token。按返回的 interval 轮询，缺省时每 5 秒一次；处理等待确认和过期响应。') }}</p>
        <p v-if="form.grant === 'password'" class="pg-notice">{{ t('For existing integrations only. Prefer Authorization Code + PKCE for new user-facing applications.', '用于已有集成；新的用户应用优先使用 Authorization Code + PKCE。') }}</p>
        <p v-if="form.grant === 'token_exchange'" class="pg-notice">{{ t('The subject must be an active local access token with a resource-owner identity. This minimal example omits the optional actor and audience/resource parameters.', 'subject 必须是包含资源所有者身份的有效本地 access token。此最小示例不包含可选的 actor 和 audience/resource 参数。') }}</p>
        <button class="pg-primary" type="submit">{{ busy ? t('Building…', '构造中…') : t('Build example', '构造示例') }}</button>
      </fieldset>
    </form>
    <p v-if="error" class="pg-error" role="alert">{{ error }}</p>
    <div v-if="result.length" class="pg-results">
      <ToolOutput v-for="output in result" :key="output.label" :label="labels[output.label]" :method="output.method" :value="output.text" />
    </div>
  </div>
</template>

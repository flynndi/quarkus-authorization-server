<script>
// A same-document route change restores the full locale without persisting the code.
let callbackHandoff
</script>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useData, useRouter } from 'vitepress'
import { decodeJwt } from './oauth-tools.mjs'
import { acceptDevice, acceptToken, createApi, demo, OAuthError, pollDevice, prepareAuthorization, readCallback, redact, transactionKey } from './live-oauth.mjs'
import ToolOutput from './ToolOutput.vue'
import './live-playground.css'

const { lang } = useData()
const router = useRouter()
const t = (en, zh) => lang.value.startsWith('zh') ? zh : en
const prefix = computed(() => lang.value.startsWith('zh') ? '/zh' : '')
const modes = [
  { id: 'authorization_code', title: 'Authorization Code', detail: ['Browser login · PKCE', '浏览器登录 · PKCE'] },
  { id: 'client_credentials', title: 'Client Credentials', detail: ['Application identity', '应用身份'] },
  { id: 'password', title: 'Password', detail: ['Demo user credentials', '演示用户凭据'] },
  { id: 'device_code', title: 'Device Authorization', detail: ['Approve on another screen', '在另一页面确认'] }
]
const mode = ref('authorization_code')
const scopes = ref([...demo.scopes])
const secret = ref(demo.clientSecret)
const username = ref(demo.username)
const password = ref(demo.password)
const metadata = ref(null)
const token = ref(null)
const pending = ref(null)
const device = ref(null)
const resource = ref(null)
const history = ref([])
const error = ref(null)
const busy = ref(false)
const activeAction = ref('')
const allowedOrigin = ref(false)
const mounted = ref(false)
const clock = ref(Date.now())
const pollingInterval = ref(5)
let controller
let ticker
const api = createApi({ record: entry => { history.value = [entry, ...history.value].slice(0, 20) } })
const connected = computed(() => Boolean(metadata.value))
const remaining = computed(() => token.value ? Math.max(0, Math.ceil((token.value.expiresAt - clock.value) / 1000)) : 0)
const deviceRemaining = computed(() => device.value ? Math.max(0, Math.ceil((device.value.expiresAt - clock.value) / 1000)) : 0)
const decoded = computed(() => {
  if (!token.value) return null
  try { return decodeJwt(token.value.access_token) } catch { return null }
})
const tokenSummary = computed(() => token.value ? {
  token_type: token.value.token_type, expires_in: token.value.expires_in,
  scope: token.value.scope ?? scopes.value.join(' '), refresh_token: token.value.refresh_token ? t('Available', '可用') : t('Not issued', '未签发')
} : null)
const errorMessages = {
  missing_secret: ['Enter the demo client secret.', '请输入演示客户端 secret。'],
  missing_password: ['Enter the demo username and password.', '请输入演示用户名和密码。'],
  missing_scope: ['Select at least one scope.', '请至少选择一个 scope。'],
  invalid_state: ['This authorization attempt has expired or does not belong to this tab. Start again.', '授权已过期或不属于此标签页，请重新开始。'],
  invalid_callback: ['The authorization callback is invalid. Start a new authorization.', '授权回调无效，请重新发起授权。'],
  invalid_metadata: ['The discovery document does not match the configured demo server.', '发现文档与演示服务器配置不一致。'],
  invalid_token_response: ['The server returned an unexpected token response.', '服务器返回了不符合预期的 Token 响应。'],
  invalid_device_response: ['The server returned an unexpected device response.', '服务器返回了不符合预期的设备授权响应。'],
  network_error: ['Could not reach the demo server. Check your connection or try again later. The browser may also have blocked CORS.', '无法连接演示服务器，请检查网络或稍后重试，也可能是浏览器拦截了 CORS。'],
  timeout: ['The request timed out. Try again when the server is reachable.', '请求超时，请稍后重试。'],
  storage: ['Temporary browser storage is unavailable. Allow session storage before starting authorization.', '临时浏览器存储不可用，请允许 sessionStorage 后重新发起授权。'],
  access_denied: ['Authorization was denied. You can start a new attempt.', '授权被拒绝，可以重新发起。'],
  expired_token: ['The device code has expired. Request a new code.', '设备码已过期，请重新申请。'],
  cancelled: ['Operation cancelled.', '操作已取消。'],
  invalid_grant: ['The grant is invalid or expired. Start a new authorization.', '授权凭据无效或过期，请重新发起授权。'],
  invalid_client: ['Client authentication failed. Check the client secret.', '客户端认证失败，请检查 secret。'],
  http_401: ['The resource requires a valid access token.', '资源需要有效的 Access Token。'],
  http_403: ['The token does not have permission to access this resource.', 'Token 没有访问此资源的权限。']
}
const errorText = computed(() => {
  if (!error.value) return ''
  const message = errorMessages[error.value.code]
  return message ? t(...message) : error.value.message || t('Request failed.', '请求失败。')
})
const primaryLabel = computed(() => {
  if (busy.value) return activeAction.value === 'device' ? t('Waiting for approval…', '等待设备确认…') : t('Requesting…', '请求中…')
  if (pending.value) return t('Exchange authorization code', '兑换授权码')
  if (mode.value === 'authorization_code') return t('Continue to sign in →', '前往登录 →')
  if (mode.value === 'device_code') return t('Get device code', '获取设备码')
  return t('Get access token', '获取 Access Token')
})

function stop() {
  controller?.abort()
  controller = null
  busy.value = false
  activeAction.value = ''
  device.value = null
}
function selectMode(value) {
  stop()
  mode.value = value
  pending.value = null
  token.value = null
  resource.value = null
  error.value = null
  password.value = demo.password
  try { sessionStorage.removeItem(transactionKey) } catch { /* No persisted token or credential. */ }
}
function clear() {
  selectMode(mode.value)
  secret.value = demo.clientSecret
  username.value = demo.username
  history.value = []
}
function leavePage() {
  // Keep PKCE across redirects; discard any overrides of the public demo credentials.
  stop()
  secret.value = demo.clientSecret
  password.value = demo.password
  token.value = null
  pending.value = null
}
async function run(action, work) {
  if (busy.value || !allowedOrigin.value) return
  const current = new AbortController()
  controller = current
  busy.value = true
  activeAction.value = action
  error.value = null
  try { await work(current.signal) } catch (failure) {
    if (!current.signal.aborted) error.value = failure
  } finally {
    if (controller === current) { busy.value = false; activeAction.value = ''; controller = null }
  }
}
async function discover(signal) {
  if (!metadata.value) {
    const result = await api.discover(signal)
    signal.throwIfAborted()
    metadata.value = result
  }
  signal.throwIfAborted()
  return metadata.value
}
function storeToken(data, signal) {
  signal.throwIfAborted()
  token.value = data
  resource.value = null
  password.value = demo.password
  clock.value = Date.now()
}
function submit() {
  return run(mode.value === 'device_code' ? 'device' : 'token', async signal => {
    if (!scopes.value.length) throw new OAuthError('missing_scope')
    if ((mode.value !== 'authorization_code' || pending.value) && !secret.value) throw new OAuthError('missing_secret')
    if (mode.value === 'password' && (!username.value || !password.value)) throw new OAuthError('missing_password')
    token.value = null
    resource.value = null
    const config = await discover(signal)
    if (mode.value === 'authorization_code' && !pending.value) {
      const prepared = await prepareAuthorization(config, [...scopes.value], lang.value)
      signal.throwIfAborted()
      try { sessionStorage.setItem(transactionKey, JSON.stringify(prepared.transaction)) } catch { throw new OAuthError('storage') }
      secret.value = demo.clientSecret
      window.location.assign(prepared.url)
      return
    }
    if (mode.value === 'device_code') {
      device.value = null
      const response = await api.request(config.device_authorization_endpoint, { secret: secret.value, signal, params: { scope: scopes.value.join(' ') } })
      signal.throwIfAborted()
      device.value = acceptDevice(response)
      try {
        const result = await pollDevice({ device: device.value, request: api.request, endpoint: config.token_endpoint, secret: secret.value, signal, update: interval => { pollingInterval.value = interval } })
        storeToken(result, signal)
      } finally {
        if (!signal.aborted) device.value = null
      }
      return
    }
    let params
    if (pending.value) {
      const { code, transaction } = pending.value
      params = { grant_type: 'authorization_code', code, redirect_uri: transaction.redirectUri, code_verifier: transaction.verifier }
    } else {
      params = { grant_type: mode.value, scope: scopes.value.join(' ') }
      if (mode.value === 'password') Object.assign(params, { username: username.value, password: password.value })
    }
    const result = await api.request(config.token_endpoint, { secret: secret.value, signal, params })
    storeToken(acceptToken(result), signal)
    pending.value = null
  })
}
function refresh() {
  return run('refresh', async signal => {
    if (!secret.value) throw new OAuthError('missing_secret')
    const config = await discover(signal)
    const refreshToken = token.value.refresh_token
    const result = await api.request(config.token_endpoint, { secret: secret.value, signal, params: { grant_type: 'refresh_token', refresh_token: refreshToken } })
    storeToken(acceptToken({ ...result, refresh_token: result.refresh_token ?? refreshToken }), signal)
  })
}
function callResource(path) {
  return run('resource', async signal => {
    resource.value = null
    try {
      const response = await api.request(`${demo.issuer}${path}`, { accessToken: token.value?.access_token, signal })
      signal.throwIfAborted()
      resource.value = { path, status: 200, body: redact(response) }
    } catch (failure) {
      if (!signal.aborted) resource.value = { path, status: failure.status || 0, body: { error: failure.code } }
      throw failure
    }
  })
}
onMounted(() => {
  mounted.value = true
  allowedOrigin.value = window.location.origin === demo.origin
  ticker = setInterval(() => { clock.value = Date.now() }, 1000)
  window.addEventListener('pagehide', leavePage)
  if (window.location.pathname.replace(/\/$/, '') !== '/playground/callback') {
    if (callbackHandoff) {
      const result = callbackHandoff
      callbackHandoff = undefined
      if (result.transaction) scopes.value = result.transaction.scopes
      if (result.error) error.value = result.error
      else pending.value = result
    }
    return
  }
  const search = window.location.search
  // Remove protocol parameters before any interaction or outgoing link is offered.
  window.history.replaceState(null, '', window.location.pathname)
  try {
    const stored = sessionStorage.getItem(transactionKey)
    sessionStorage.removeItem(transactionKey)
    callbackHandoff = readCallback(search, stored)
  } catch (failure) { callbackHandoff = { error: failure } }
  const destination = callbackHandoff.transaction?.locale?.startsWith('zh') ? '/zh/playground/' : '/playground/'
  router.go(destination)
})
onBeforeUnmount(() => { stop(); clearInterval(ticker); window.removeEventListener('pagehide', leavePage) })
</script>

<template>
  <main class="live-page">
    <header class="live-heading">
      <div>
        <p class="live-eyebrow">OAUTH 2.0 · {{ t('EXPERIMENTAL COMMUNITY DEMO', '实验性社区演示') }}</p>
        <h1>{{ t('From authorization to API.', '从授权到资源访问。') }}</h1>
        <p class="live-lead">{{ t('Choose a flow. Get a token. See what it can access.', '选择授权模式，获取 Token，查看它能访问哪些资源。') }}</p>
      </div>
      <div class="live-server"><span :class="{ connected }"></span><div><strong>{{ connected ? t('Discovery verified', '发现配置已核验') : t('Demo server', '演示服务器') }}</strong><a :href="demo.issuer + '/.well-known/openid-configuration'" target="_blank" rel="noopener noreferrer">auth.quarkus-authorization-server.dev ↗</a></div></div>
    </header>

    <p v-if="mounted && !allowedOrigin" class="live-notice">{{ t('Preview mode: live requests are enabled only on authorization-server.dev.', '预览模式：仅在 authorization-server.dev 启用真实请求。') }}</p>

    <nav class="live-modes" :aria-label="t('Authorization flow', '授权模式')">
      <button v-for="(item, i) in modes" :key="item.id" :aria-pressed="mode === item.id" :class="{ selected: mode === item.id }" @click="selectMode(item.id)">
        <small>0{{ i + 1 }}</small><strong>{{ item.title }}</strong><span>{{ t(...item.detail) }}</span>
      </button>
    </nav>

    <div class="live-workspace">
      <section class="live-panel live-request" :aria-label="t('Request configuration', '请求配置')">
        <div class="live-section-title"><span>01 / {{ t('CONFIGURE', '配置请求') }}</span><button type="button" class="live-link" @click="clear">{{ t('Reset', '重置') }}</button></div>
        <h2>{{ modes.find(item => item.id === mode).title }}<small v-if="mode === 'authorization_code'"> + PKCE</small></h2>
        <p class="live-help" v-if="mode === 'authorization_code'">{{ t('Sign in and consent on the authorization server, then exchange the returned code. User login and client authentication are separate steps; the demo client secret is prefilled.', '在授权服务器完成登录与同意，返回后兑换授权码。用户登录与客户端认证是两个步骤，演示客户端 secret 已预填。') }}</p>
        <p class="live-help" v-else-if="mode === 'client_credentials'">{{ t('The application acts on its own behalf. No user login is involved.', '应用以自身身份访问资源，不涉及用户登录。') }}</p>
        <p class="live-help" v-else-if="mode === 'password'">{{ t('An existing Password grant demonstration. Use demo credentials only; new applications should use Authorization Code + PKCE.', '演示已有的 Password grant，仅使用演示账号；新应用应选择 Authorization Code + PKCE。') }}</p>
        <p class="live-help" v-else>{{ t('Request a code, open the verification page and approve. This page waits for the token.', '申请设备码后，打开确认页面完成授权，此页面会等待 Token。') }}</p>

        <form @submit.prevent="submit">
          <fieldset :disabled="busy">
            <label class="live-field">Client ID<input :value="demo.clientId" readonly spellcheck="false"></label>
            <div class="live-auth-type">client_secret_basic <span>· {{ t('shared demo client', '通用演示客户端') }}</span></div>
            <label class="live-field">Client secret<input v-model="secret" type="text" autocomplete="off" :placeholder="t('Enter the demo client secret', '输入演示客户端 secret')" spellcheck="false"></label>
            <p v-if="mode === 'authorization_code' || mode === 'device_code'" class="live-demo-login">{{ t('Demo sign-in', '演示登录账号') }}: <code>{{ demo.username }}</code> / <code>{{ demo.password }}</code></p>
            <template v-if="mode === 'password'">
              <label class="live-field">{{ t('Username', '用户名') }}<input v-model="username" autocomplete="off" spellcheck="false"></label>
              <label class="live-field">{{ t('Password', '密码') }}<input v-model="password" type="text" autocomplete="off" :placeholder="t('Enter the demo password', '输入演示密码')" spellcheck="false"></label>
            </template>
            <fieldset class="live-scopes" :disabled="Boolean(pending) || busy"><legend>{{ t('Requested scopes', '申请的 Scope') }}</legend><label v-for="scope in demo.scopes" :key="scope"><input type="checkbox" v-model="scopes" :value="scope"><code>{{ scope }}</code></label></fieldset>
            <p v-if="pending" class="live-notice">{{ t('Authorization approved. The demo client secret is prefilled; exchange the code to continue. Reloading discards this code.', '授权已同意，演示客户端 secret 已预填，点击兑换授权码继续。刷新页面会丢弃此授权码。') }}</p>
            <button class="live-primary" :disabled="!allowedOrigin || busy" type="submit">{{ primaryLabel }}</button>
          </fieldset>
        </form>
        <button v-if="busy" class="live-link live-cancel" @click="stop">{{ t('Cancel request', '取消请求') }}</button>
        <div v-if="device" class="live-device" aria-live="polite">
          <span>{{ t('Your user code', '用户码') }}</span><strong>{{ device.user_code }}</strong>
          <a :href="device.verification_uri" target="_blank" rel="noopener noreferrer">{{ t('Open verification page ↗', '打开设备确认页 ↗') }}</a>
          <p>{{ deviceRemaining }}s {{ t('remaining', '后过期') }} · {{ t('Poll interval', '轮询间隔') }} {{ pollingInterval }}s</p>
        </div>
        <p v-if="error" class="live-error" role="alert"><strong>{{ error.code || 'error' }}</strong>{{ errorText }}</p>
        <p class="live-footnote">{{ t('Public demo credentials are prefilled. Edited values and tokens stay in memory; redirect state and PKCE use temporary session storage. Reset restores the demo defaults.', '公开演示凭据已预填。修改后的值与 Token 保留在内存；跳转状态与 PKCE 使用临时会话存储。重置会恢复演示默认值。') }}</p>
      </section>

      <div class="live-results">
        <section class="live-panel" :aria-label="t('Token result', 'Token 结果')">
          <div class="live-section-title"><span>02 / TOKEN</span><span v-if="token" class="live-status" :class="{ expired: !remaining }">{{ remaining ? `${remaining}s ${t('remaining', '剩余')}` : t('Expired', '已过期') }}</span></div>
          <template v-if="token">
            <div class="live-token-title"><h2>{{ token.token_type }} access token</h2><button v-if="token.refresh_token" :disabled="busy" class="live-link" @click="refresh">{{ t('Refresh token', '刷新 Token') }}</button></div>
            <dl class="live-token-facts"><template v-for="(value, key) in tokenSummary" :key="key"><dt>{{ key }}</dt><dd>{{ value }}</dd></template></dl>
            <details class="live-details" open v-if="decoded"><summary>{{ t('Decoded claims', '解码后的 Claims') }} <span>{{ t('not signature verification', '不代表签名验证') }}</span></summary><pre>{{ JSON.stringify(decoded.payload, null, 2) }}</pre></details>
            <details class="live-details"><summary>{{ t('View / copy tokens', '查看 / 复制 Token') }}</summary><div class="pg-tool live-token-output"><ToolOutput label="Access token" :value="token.access_token"/><ToolOutput v-if="token.refresh_token" label="Refresh token" :value="token.refresh_token"/></div></details>
          </template>
          <div v-else class="live-empty"><div class="live-empty-symbol" aria-hidden="true">{ }</div><h2>{{ t('Your token will appear here', 'Token 将显示在这里') }}</h2><p>{{ t('Complete a flow to inspect its claims and call the resource server.', '完成授权后，查看 Claims 并调用资源服务器。') }}</p><div class="live-flow"><span>{{ t('Authorize', '授权') }}</span><span>→</span><span>Token</span><span>→</span><span>API</span></div></div>
        </section>

        <section class="live-panel" :aria-label="t('Resource server', '资源服务器')">
          <div class="live-section-title"><span>03 / {{ t('RESOURCE SERVER', '资源服务器') }}</span><span class="live-subtle">Bearer</span></div>
          <h2>{{ t('Put the scopes to work.', '看看 Scope 的作用。') }}</h2>
          <p class="live-help">{{ t('Each API requires its matching scope. Missing token → 401. Missing scope → 403.', '每个 API 需要同名 scope。未携带 Token → 401，缺少 Scope → 403。') }}</p>
          <button v-for="path in demo.resources" :key="path" class="live-resource-button" :disabled="busy || !allowedOrigin" @click="callResource(path)"><span>GET</span><code>{{ path }}</code><span aria-hidden="true">↗</span></button>
          <div v-if="resource" class="live-resource-result" aria-live="polite"><strong :class="{ failed: resource.status !== 200 }">{{ resource.status || t('Network error', '网络错误') }}</strong><span>{{ resource.path }}</span><pre>{{ JSON.stringify(resource.body, null, 2) }}</pre><small>{{ t('Embedded raw tokens and credentials are redacted.', '响应内的原始 Token 和凭据已脱敏。') }}</small></div>
        </section>
      </div>
    </div>

    <section class="live-panel live-history" :aria-label="t('Request history', '请求记录')">
      <div class="live-section-title"><span>{{ t('REQUEST LOG', '请求记录') }}</span><span>{{ history.length }} / 20</span></div>
      <p v-if="!history.length" class="live-help">{{ t('Requests appear as you interact. Credentials and tokens are redacted from this log.', '操作后会显示请求记录，其中的凭据和 Token 已脱敏。') }}</p>
      <details v-for="(entry, i) in history" :key="history.length + ':' + i" class="live-log-entry"><summary><span class="live-method">{{ entry.method }}</span><span class="live-log-path">{{ entry.url.replace(demo.issuer, '') }}</span><strong :class="{ failed: entry.status < 200 || entry.status >= 300 }">{{ entry.status || '—' }}</strong><small>{{ entry.duration }}ms</small></summary><pre>{{ JSON.stringify({ request: entry.request, response: entry.response }, null, 2) }}</pre></details>
    </section>
    <footer class="live-tools"><span>{{ t('Explore offline', '离线工具') }}</span><a :href="`${prefix}/playground/pkce`">PKCE {{ t('generator', '生成器') }} ↗</a><a :href="`${prefix}/playground/jwt`">JWT {{ t('decoder', '解码') }} ↗</a><a :href="`${prefix}/playground/requests`">{{ t('Request builder', '请求构造器') }} ↗</a></footer>
  </main>
</template>

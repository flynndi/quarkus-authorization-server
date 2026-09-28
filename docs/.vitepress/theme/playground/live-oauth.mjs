import { randomValue, s256 } from './oauth-tools.mjs'

// The live demo has one fixed backend. Never send credentials to a user-supplied URL.
export const demo = Object.freeze({
  issuer: 'https://auth.quarkus-authorization-server.dev',
  origin: 'https://authorization-server.dev',
  clientId: 'quarkus-authorization-server',
  // Public sandbox credentials, intentionally included in the demo at the owner's request.
  clientSecret: 'quarkus-authorization-server-password',
  username: 'admin',
  password: 'password',
  redirectUri: 'https://authorization-server.dev/playground/callback',
  scopes: ['securityIdentity', 'jsonWebToken'],
  resources: ['/api/resource/securityIdentity', '/api/resource/jsonWebToken']
})
export const transactionKey = 'qas.playground.authorization'
const transactionLifetime = 10 * 60 * 1000
const sensitive = /^(authorization|access_token|refresh_token|id_token|rawToken|credential|client_secret|password|code|device_code|user_code|code_verifier|verification_uri_complete)$/i

export class OAuthError extends Error {
  constructor(code, description = '', status = 0) {
    super(description || code)
    this.code = code
    this.status = status
  }
}

export function redact(value) {
  if (Array.isArray(value)) return value.map(redact)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sensitive.test(key) ? '[redacted]' : redact(item)]))
  }
  return value
}

export function trustedEndpoint(value) {
  let url
  try { url = new URL(value) } catch { throw new OAuthError('invalid_metadata') }
  if (url.origin !== demo.issuer || url.username || url.password || url.hash || url.search) {
    throw new OAuthError('invalid_metadata')
  }
  return url.href
}

export function basicAuth(secret) {
  if (!secret) throw new OAuthError('missing_secret')
  // OAuth Basic uses application/x-www-form-urlencoded encoding before base64.
  const encode = value => new URLSearchParams({ v: value }).toString().slice(2)
  return `Basic ${btoa(`${encode(demo.clientId)}:${encode(secret)}`)}`
}

export function createApi({ fetcher = globalThis.fetch, record = () => {}, timeout = 15000 } = {}) {
  async function request(endpoint, { params, secret, accessToken, signal } = {}) {
    trustedEndpoint(endpoint)
    const authorization = secret !== undefined ? basicAuth(secret) : accessToken ? `Bearer ${accessToken}` : undefined
    const controller = new AbortController()
    const cancel = () => controller.abort()
    signal?.throwIfAborted()
    signal?.addEventListener('abort', cancel, { once: true })
    const timer = setTimeout(cancel, timeout)
    const method = params ? 'POST' : 'GET'
    const headers = { Accept: 'application/json' }
    if (params) headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if (authorization) headers.Authorization = authorization
    const entry = { method, url: endpoint, request: { headers: redact(headers), ...(params ? { body: redact(params) } : {}) } }
    const start = Date.now()
    try {
      const response = await fetcher(endpoint, {
        method, headers, body: params ? new URLSearchParams(params) : undefined,
        credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal
      })
      const text = await response.text()
      let data
      try { data = text ? JSON.parse(text) : null } catch { data = { message: 'Non-JSON response' } }
      record({ ...entry, status: response.status, duration: Date.now() - start, response: redact(data) })
      if (!response.ok) throw new OAuthError(data?.error || `http_${response.status}`, data?.error_description || '', response.status)
      return data
    } catch (error) {
      if (error instanceof OAuthError) throw error
      const code = signal?.aborted ? 'cancelled' : controller.signal.aborted ? 'timeout' : 'network_error'
      record({ ...entry, status: 0, duration: Date.now() - start, response: { error: code } })
      throw new OAuthError(code)
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', cancel)
    }
  }
  async function discover(signal) {
    const metadata = await request(`${demo.issuer}/.well-known/openid-configuration`, { signal })
    if (metadata?.issuer !== demo.issuer) throw new OAuthError('invalid_metadata')
    for (const key of ['authorization_endpoint', 'token_endpoint', 'device_authorization_endpoint']) trustedEndpoint(metadata[key])
    if (!metadata.code_challenge_methods_supported?.includes('S256') || !metadata.token_endpoint_auth_methods_supported?.includes('client_secret_basic')) {
      throw new OAuthError('invalid_metadata')
    }
    return metadata
  }
  return { request, discover }
}

export async function prepareAuthorization(metadata, scopes, locale, now = Date.now()) {
  const verifier = randomValue()
  const transaction = { state: randomValue(), verifier, scopes, locale, createdAt: now, redirectUri: demo.redirectUri }
  const url = new URL(trustedEndpoint(metadata.authorization_endpoint))
  url.search = new URLSearchParams({
    response_type: 'code', client_id: demo.clientId, redirect_uri: demo.redirectUri,
    scope: scopes.join(' '), state: transaction.state,
    code_challenge: await s256(verifier), code_challenge_method: 'S256'
  }).toString()
  return { transaction, url: url.href }
}

export function readCallback(search, stored, now = Date.now()) {
  const params = new URLSearchParams(search)
  for (const key of ['state', 'code', 'error', 'error_description', 'iss']) {
    if (params.getAll(key).length > 1) throw new OAuthError('invalid_callback')
  }
  let transaction
  try { transaction = JSON.parse(stored) } catch { throw new OAuthError('invalid_state') }
  if (!transaction || !params.get('state') || params.get('state') !== transaction.state ||
      transaction.redirectUri !== demo.redirectUri || !/^[A-Za-z0-9._~-]{43,128}$/.test(transaction.verifier) ||
      !Array.isArray(transaction.scopes) || !transaction.scopes.every(scope => demo.scopes.includes(scope)) ||
      !Number.isFinite(transaction.createdAt) || now < transaction.createdAt || now - transaction.createdAt > transactionLifetime) {
    throw new OAuthError('invalid_state')
  }
  if (params.has('iss') && params.get('iss') !== demo.issuer) throw new OAuthError('invalid_callback')
  if (params.has('error') && params.has('code')) throw new OAuthError('invalid_callback')
  if (params.has('error')) return { transaction, error: new OAuthError(params.get('error'), params.get('error_description') || '') }
  if (!params.get('code')) throw new OAuthError('invalid_callback')
  return { transaction, code: params.get('code') }
}

export function acceptToken(data, now = Date.now()) {
  if (!data || typeof data.access_token !== 'string' || !data.access_token ||
      typeof data.token_type !== 'string' || data.token_type.toLowerCase() !== 'bearer' ||
      !Number.isFinite(data.expires_in) || data.expires_in <= 0) throw new OAuthError('invalid_token_response')
  return { ...data, receivedAt: now, expiresAt: now + data.expires_in * 1000 }
}

export function acceptDevice(data, now = Date.now()) {
  if (!data || !data.device_code || !data.user_code || !Number.isFinite(data.expires_in) || data.expires_in <= 0 ||
      (data.interval !== undefined && (!Number.isFinite(data.interval) || data.interval <= 0))) throw new OAuthError('invalid_device_response')
  trustedEndpoint(data.verification_uri)
  // Use the plain verification URI; the user code remains visible and explicit.
  return { ...data, interval: data.interval ?? 5, expiresAt: now + data.expires_in * 1000 }
}

export function pause(ms, signal) {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted()
    const abort = () => { clearTimeout(timer); reject(new OAuthError('cancelled')) }
    const timer = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve() }, ms)
    signal?.addEventListener('abort', abort, { once: true })
  })
}

export async function pollDevice({ device, request, endpoint, secret, signal, update = () => {}, wait = pause, now = Date.now }) {
  let interval = device.interval
  while (now() < device.expiresAt) {
    update(interval)
    await wait(Math.min(interval * 1000, device.expiresAt - now()), signal)
    signal?.throwIfAborted()
    if (now() >= device.expiresAt) break
    try {
      const data = await request(endpoint, { secret, signal, params: {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: device.device_code
      } })
      return acceptToken(data, now())
    } catch (error) {
      if (error.code === 'slow_down') interval += 5
      else if (error.code === 'timeout') interval *= 2
      else if (error.code !== 'authorization_pending') throw error
    }
  }
  throw new OAuthError('expired_token')
}

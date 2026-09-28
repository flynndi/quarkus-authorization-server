import test from 'node:test'
import assert from 'node:assert/strict'
import { acceptDevice, acceptToken, basicAuth, createApi, demo, OAuthError, pollDevice, prepareAuthorization, readCallback, redact, trustedEndpoint } from '../.vitepress/theme/playground/live-oauth.mjs'
import { s256 } from '../.vitepress/theme/playground/oauth-tools.mjs'

const metadata = {
  issuer: demo.issuer, authorization_endpoint: demo.issuer + '/oauth2/authorize', token_endpoint: demo.issuer + '/oauth2/token',
  device_authorization_endpoint: demo.issuer + '/oauth2/device_authorization',
  code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['client_secret_basic']
}
const token = { access_token: 'test-token', token_type: 'Bearer', expires_in: 300 }
const codeIs = code => error => error.code === code
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

test('authorization binds S256, fixed client/callback, scopes and locale without saving credentials', async () => {
  const { transaction, url } = await prepareAuthorization(metadata, ['securityIdentity'], 'zh-CN', 1000)
  const params = new URL(url).searchParams
  assert.equal(params.get('code_challenge'), await s256(transaction.verifier))
  assert.equal(params.get('redirect_uri'), demo.redirectUri)
  assert.equal(params.get('client_id'), demo.clientId)
  assert.equal(params.get('scope'), 'securityIdentity')
  const result = readCallback(new URLSearchParams({ code: 'returned-code', state: transaction.state }).toString(), JSON.stringify(transaction), 2000)
  assert.equal(result.code, 'returned-code')
  assert.equal(result.transaction.locale, 'zh-CN')
  assert.deepEqual(Object.keys(transaction).sort(), ['createdAt', 'locale', 'redirectUri', 'scopes', 'state', 'verifier'])
})

test('callback rejects unsolicited, expired, duplicate, origin-mismatched, issuer-mismatched and mixed responses', async () => {
  const { transaction } = await prepareAuthorization(metadata, demo.scopes, 'en-US', 1000)
  const stored = JSON.stringify(transaction)
  const valid = `state=${transaction.state}&code=one`
  for (const [query, storage, now] of [
    [valid, null, 2000], ['state=foreign&code=one', stored, 2000], [valid, stored, 602000], [valid, stored, 0],
    [valid + '&code=two', stored, 2000], [valid + '&state=foreign', stored, 2000],
    [valid + '&iss=https://attacker.example', stored, 2000], [valid + '&error=access_denied', stored, 2000],
    [valid, JSON.stringify({ ...transaction, redirectUri: 'https://another-docs.example/playground/callback' }), 2000]
  ]) assert.throws(() => readCallback(query, storage, now), OAuthError)
  const result = readCallback(`state=${transaction.state}&error=access_denied`, stored, 2000)
  assert.equal(result.error.code, 'access_denied')
})

test('credentials never go to a foreign, insecure, credentialed or redirected endpoint', async () => {
  for (const url of ['http://auth.quarkus-authorization-server.dev/token', 'https://attacker.example/token', `${demo.issuer}@attacker.example/token`, demo.issuer + '/token?next=evil', demo.issuer + '/token#fragment']) {
    assert.throws(() => trustedEndpoint(url), codeIs('invalid_metadata'))
  }
  const api = createApi({ fetcher: async () => json({ ...metadata, token_endpoint: 'https://attacker.example/token' }) })
  await assert.rejects(api.discover(), codeIs('invalid_metadata'))
})

test('Basic encodes each field with OAuth form encoding before base64', () => {
  assert.equal(atob(basicAuth('a b:c/汉').slice(6)), `${demo.clientId}:a+b%3Ac%2F%E6%B1%89`)
  assert.throws(() => basicAuth(''), codeIs('missing_secret'))
})

test('request uses explicit Basic, omits cookies, blocks redirects and redacts log', async () => {
  const entries = []
  const api = createApi({ record: entry => entries.push(entry), fetcher: async (url, init) => {
    assert.equal(init.credentials, 'omit')
    assert.equal(init.redirect, 'error')
    assert.equal(init.cache, 'no-store')
    assert.equal(init.headers.Authorization, basicAuth('a-secret'))
    assert.equal(init.body.get('password'), 'a-password')
    return json({ ...token, refresh_token: 'refresh-secret' })
  } })
  const result = await api.request(metadata.token_endpoint, { secret: 'a-secret', params: { grant_type: 'password', password: 'a-password' } })
  assert.equal(result.access_token, 'test-token')
  const log = JSON.stringify(entries)
  for (const value of ['a-secret', 'a-password', 'test-token', 'refresh-secret', basicAuth('a-secret')]) assert.equal(log.includes(value), false)
})

test('resource payload nested credentials and raw tokens are redacted without dropping claims', () => {
  const result = redact({ rawToken: 'secret', credential: { token: 'secret' }, claims: { sub: 'admin', scope: ['securityIdentity'] } })
  assert.equal(result.rawToken, '[redacted]')
  assert.equal(result.credential, '[redacted]')
  assert.equal(result.claims.sub, 'admin')
})

test('HTTP, network, timeout and cancellation remain distinguishable', async () => {
  const denied = createApi({ fetcher: async () => json({ error: 'invalid_client' }, 401) })
  await assert.rejects(denied.request(metadata.token_endpoint), e => e.code === 'invalid_client' && e.status === 401)
  const offline = createApi({ fetcher: async () => { throw new TypeError('fetch failed') } })
  await assert.rejects(offline.request(metadata.token_endpoint), codeIs('network_error'))
  const stalled = createApi({ timeout: 5, fetcher: async (_, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })) })
  await assert.rejects(stalled.request(metadata.token_endpoint), codeIs('timeout'))
  const controller = new AbortController()
  const request = stalled.request(metadata.token_endpoint, { signal: controller.signal })
  controller.abort()
  await assert.rejects(request, codeIs('cancelled'))
})

test('token response enforces Bearer with a finite lifetime', () => {
  assert.equal(acceptToken(token, 1000).expiresAt, 301000)
  for (const response of [{}, { ...token, token_type: 'DPoP' }, { ...token, expires_in: -1 }, { ...token, expires_in: Infinity }]) {
    assert.throws(() => acceptToken(response), codeIs('invalid_token_response'))
  }
})

test('device default interval is five seconds and verification stays on the issuer', () => {
  const response = { device_code: 'device', user_code: 'user', expires_in: 300, verification_uri: demo.issuer + '/oauth2/device_verification' }
  assert.equal(acceptDevice(response, 0).interval, 5)
  assert.throws(() => acceptDevice({ ...response, verification_uri: 'https://evil.example' }), codeIs('invalid_metadata'))
})

test('device polling waits before first request, honors pending/slow_down and backs off timeouts', async () => {
  let now = 0
  const waits = []
  const outcomes = ['authorization_pending', 'slow_down', 'timeout', token]
  const result = await pollDevice({
    device: { device_code: 'device', interval: 5, expiresAt: 100000 }, endpoint: metadata.token_endpoint, secret: 'secret', now: () => now,
    wait: async ms => { waits.push(ms); now += ms },
    request: async (_, init) => {
      assert.equal(init.params.grant_type, 'urn:ietf:params:oauth:grant-type:device_code')
      const next = outcomes.shift()
      if (typeof next === 'string') throw new OAuthError(next)
      return next
    }
  })
  assert.deepEqual(waits, [5000, 5000, 10000, 20000])
  assert.equal(result.access_token, token.access_token)
})

test('device polling terminates on expiry, denial or cancellation', async () => {
  let now = 0
  const base = { device: { device_code: 'device', interval: 5, expiresAt: 3000 }, now: () => now, wait: async ms => { now += ms }, request: async () => { assert.fail('expired code must not be sent') } }
  await assert.rejects(pollDevice(base), codeIs('expired_token'))
  await assert.rejects(pollDevice({ ...base, device: { ...base.device, expiresAt: 20000 }, request: async () => { throw new OAuthError('access_denied') } }), codeIs('access_denied'))
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(pollDevice({ ...base, signal: controller.signal, device: { ...base.device, expiresAt: 20000 } }))
})

import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import test from 'node:test'
import { buildRequests, decodeJwt, grants, jwtExample, pkceExample, randomValue, s256 } from '../.vitepress/theme/playground/oauth-tools.mjs'

const defaults = {
  grant: 'authorization_code', auth: 'none', clientId: 'demo-client', scope: 'openid profile',
  authorizationEndpoint: 'https://as.example/tenant/oauth2/authorize',
  tokenEndpoint: 'https://as.example/tenant/oauth2/token',
  deviceEndpoint: 'https://as.example/tenant/oauth2/device_authorization',
  redirectUri: 'http://localhost:5173/callback?lang=zh&next=%2F'
}

// Execute only a shell function standing in for curl: no subprocess can make an HTTP request.
function curlArgs(command) {
  const output = execFileSync('/bin/sh', ['-c', `curl() { printf '%s\\0' "$@"; }\n${command}`], { encoding: 'utf8' })
  return output.split('\0').slice(0, -1)
}
function form(args) {
  return new URLSearchParams(args.flatMap((arg, i) => arg === '--data-urlencode' ? [args[i + 1]] : []).map(value => {
    const separator = value.indexOf('=')
    return [value.slice(0, separator), value.slice(separator + 1)]
  }))
}
const encoded = value => Buffer.from(JSON.stringify(value)).toString('base64url')
const jwt = (header, payload, signature = '') => [encoded(header), encoded(payload), signature].join('.')
const errorCode = expected => error => error.code === expected

test('S256 matches RFC 7636 Appendix B and generates 256-bit unpadded verifiers', async () => {
  assert.equal(await s256(pkceExample.verifier, webcrypto), pkceExample.challenge)
  const first = randomValue(webcrypto)
  assert.match(first, /^[A-Za-z0-9_-]{43}$/)
  assert.notEqual(first, randomValue(webcrypto))
  assert.equal(Buffer.from(first, 'base64url').length, 32)
  assert.match(await s256(first, webcrypto), /^[A-Za-z0-9_-]{43}$/)
})

test('PKCE enforces RFC length and alphabet, and reports missing Web Crypto', async () => {
  for (const verifier of ['a'.repeat(42), 'a'.repeat(129), 'é'.repeat(43), ' '.repeat(43), pkceExample.verifier + '\n']) {
    await assert.rejects(s256(verifier, webcrypto), errorCode('verifier'))
  }
  await assert.doesNotReject(s256('a.~_-'.repeat(25), webcrypto))
  assert.throws(() => randomValue({}), errorCode('crypto'))
  await assert.rejects(s256(pkceExample.verifier, {}), errorCode('crypto'))
})

test('JWT decoding preserves Unicode and arbitrary claims without interpreting validity', () => {
  assert.equal(decodeJwt(jwtExample).payload.name, 'Demo 用户')
  const payload = { name: '中文 🐱', exp: 1, role: 'admin', html: '<img src=x onerror=alert(1)>' }
  assert.deepEqual(decodeJwt(jwt({ alg: 'none' }, payload)).payload, payload)
  assert.equal(decodeJwt(jwt({ alg: 'RS256' }, payload, 'ZmFrZQ')).header.alg, 'RS256')
})

test('JWT errors distinguish format, base64url, JSON, encryption and size', () => {
  for (const [token, code] of [
    ['opaque-token', 'segments'], ['a.b.c.d.e', 'encrypted'], ['Bearer ' + jwtExample, 'base64'],
    ['e30=.e30.', 'base64'], ['e31.e30.', 'base64'], ['a.e30.', 'base64'],
    ['_w.e30.', 'json'], [jwt({}, []), 'json'], [jwt({}, null), 'json'],
    [jwt({ b64: false }, {}), 'unencoded'], ['x'.repeat(65537), 'size']
  ]) assert.throws(() => decodeJwt(token), errorCode(code))
})

test('Authorization URL and code exchange share PKCE and exact redirect URI', async () => {
  const outputs = await buildRequests({ ...defaults, clientId: '测试 app&=1' }, webcrypto)
  const url = new URL(outputs[1].text)
  const request = form(curlArgs(outputs[2].text))
  assert.equal(url.pathname, '/tenant/oauth2/authorize')
  assert.equal(url.searchParams.get('client_id'), '测试 app&=1')
  assert.equal(url.searchParams.get('redirect_uri'), defaults.redirectUri)
  assert.equal(url.searchParams.get('code_challenge'), await s256(outputs[0].text, webcrypto))
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
  assert.equal(url.searchParams.get('response_type'), 'code')
  assert.match(url.searchParams.get('state'), /^[A-Za-z0-9_-]{43}$/)
  assert.match(url.searchParams.get('nonce'), /^[A-Za-z0-9_-]{43}$/)
  assert.notEqual(url.searchParams.get('state'), url.searchParams.get('nonce'))
  assert.equal([...url.searchParams.keys()].length, new Set(url.searchParams.keys()).size)
  assert.equal(request.get('code_verifier'), outputs[0].text)
  assert.equal(request.get('redirect_uri'), defaults.redirectUri)
  assert.equal(request.get('code'), 'REPLACE_WITH_AUTHORIZATION_CODE')
  assert.equal(request.get('client_id'), '测试 app&=1')
})

test('Code without openid omits nonce; rebuilding rotates PKCE and state', async () => {
  const a = await buildRequests({ ...defaults, scope: '' }, webcrypto)
  const b = await buildRequests({ ...defaults, scope: '' }, webcrypto)
  assert.notEqual(a[0].text, b[0].text)
  const params = new URL(a[1].text).searchParams
  assert.equal(params.has('nonce'), false)
  assert.equal(params.has('scope'), false)
  assert.notEqual(params.get('state'), new URL(b[1].text).searchParams.get('state'))
})

test('Each token grant has correct required parameters and placeholders', async () => {
  for (const grant of grants.filter(value => value !== 'authorization_code')) {
    const output = await buildRequests({ ...defaults, grant, auth: 'client_secret_basic', scope: '' })
    const args = curlArgs(output.at(-1).text)
    assert.equal(args[args.indexOf('--url') + 1], defaults.tokenEndpoint)
    assert.equal(args[args.indexOf('--user') + 1], 'demo-client:REPLACE_WITH_CLIENT_SECRET')
    const fields = form(args)
    const expectedGrant = grant === 'device_code' ? 'urn:ietf:params:oauth:grant-type:device_code'
      : grant === 'token_exchange' ? 'urn:ietf:params:oauth:grant-type:token-exchange' : grant
    assert.equal(fields.get('grant_type'), expectedGrant)
    assert.equal(fields.has('scope'), false)
    assert.equal(fields.has('client_id'), false)
    if (grant === 'refresh_token') assert.equal(fields.get('refresh_token'), 'REPLACE_WITH_REFRESH_TOKEN')
    if (grant === 'device_code') assert.equal(fields.get('device_code'), 'REPLACE_WITH_DEVICE_CODE')
    if (grant === 'password') {
      assert.equal(fields.get('username'), 'REPLACE_WITH_USERNAME')
      assert.equal(fields.get('password'), 'REPLACE_WITH_PASSWORD')
    }
    if (grant === 'token_exchange') {
      assert.equal(fields.get('subject_token'), 'REPLACE_WITH_SUBJECT_TOKEN')
      assert.equal(fields.get('subject_token_type'), 'urn:ietf:params:oauth:token-type:access_token')
    }
  }
})

test('Device authorization and polling use client_id for public clients', async () => {
  const outputs = await buildRequests({ ...defaults, grant: 'device_code' })
  const initial = curlArgs(outputs[0].text)
  assert.equal(initial[initial.indexOf('--url') + 1], defaults.deviceEndpoint)
  assert.equal(form(initial).get('scope'), defaults.scope)
  assert.equal(form(initial).has('grant_type'), false)
  for (const output of outputs) {
    const args = curlArgs(output.text)
    assert.equal(args.includes('--user'), false)
    assert.equal(form(args).get('client_id'), defaults.clientId)
  }
})

test('curl shell quoting preserves hostile input as a single form value', async () => {
  const scope = "read'; printf INJECTED; #\n$(printf substituted) `printf backticks` &a=b"
  const [output] = await buildRequests({ ...defaults, grant: 'client_credentials', auth: 'client_secret_basic', scope, clientId: 'a:测试 +&' })
  const args = curlArgs(output.text)
  assert.equal(form(args).get('scope'), scope)
  assert.equal(args[args.indexOf('--user') + 1], 'a%3A%E6%B5%8B%E8%AF%95+%2B%26:REPLACE_WITH_CLIENT_SECRET')
})

test('Reject dangerous, ambiguous or incomplete request configuration', async () => {
  for (const [change, code] of [
    [{ tokenEndpoint: 'javascript:alert(1)' }, 'url'], [{ tokenEndpoint: '//as.example/token' }, 'url'],
    [{ tokenEndpoint: 'https://user:secret@as.example/token' }, 'url'], [{ tokenEndpoint: 'https://as.example/token#x' }, 'url'],
    [{ authorizationEndpoint: 'https://as.example/authorize?client_id=old' }, 'query'],
    [{ tokenEndpoint: 'https://as.example/to\nken' }, 'url'], [{ redirectUri: 'https://app.example/callback#' }, 'redirect'],
    [{ redirectUri: 'https://app.example/#callback' }, 'redirect'], [{ clientId: ' ' }, 'required'],
    [{ grant: 'refresh_token', auth: 'none' }, 'auth'], [{ grant: 'implicit' }, 'grant']
  ]) await assert.rejects(buildRequests({ ...defaults, ...change }, webcrypto), errorCode(code))
})

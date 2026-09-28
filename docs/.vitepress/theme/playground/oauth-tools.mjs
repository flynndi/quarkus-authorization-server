// Shared by browser components and node:test. No network or browser storage access.
export const pkceExample = {
  verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
}

export class ToolError extends Error {
  constructor(code, field) {
    super(code)
    this.code = code
    this.field = field
  }
}

function base64url(bytes) {
  return btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

export function randomValue(crypto = globalThis.crypto) {
  if (!crypto?.getRandomValues) throw new ToolError('crypto')
  return base64url(crypto.getRandomValues(new Uint8Array(32)))
}

export async function s256(verifier, crypto = globalThis.crypto) {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) throw new ToolError('verifier')
  if (!crypto?.subtle) throw new ToolError('crypto')
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))))
}

function decodeSegment(segment) {
  if (!/^[A-Za-z0-9_-]+$/.test(segment) || segment.length % 4 === 1) throw new ToolError('base64')
  const bytes = Uint8Array.from(atob(segment.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - segment.length % 4) % 4)), char => char.charCodeAt(0))
  if (base64url(bytes) !== segment) throw new ToolError('base64')
  return bytes
}

function decodeObject(segment) {
  const bytes = decodeSegment(segment)
  let object
  try {
    object = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    throw new ToolError('json')
  }
  if (!object || typeof object !== 'object' || Array.isArray(object)) throw new ToolError('json')
  return object
}

export function decodeJwt(input) {
  if (input.length > 65536) throw new ToolError('size')
  const segments = input.trim().split('.')
  if (segments.length === 5) throw new ToolError('encrypted')
  if (segments.length !== 3) throw new ToolError('segments')
  const header = decodeObject(segments[0])
  if (header.b64 === false) throw new ToolError('unencoded')
  const payload = decodeObject(segments[1])
  // Check only the compact encoding, never the signature, algorithm or claims.
  if (segments[2]) decodeSegment(segments[2])
  return { header, payload }
}

export const jwtExample = [
  { alg: 'RS256', typ: 'JWT' },
  { iss: 'https://as.example', sub: 'demo-user', aud: 'demo-api', scope: 'message.read', name: 'Demo 用户' }
].map(value => base64url(new TextEncoder().encode(JSON.stringify(value))))
  .concat(base64url(new TextEncoder().encode('example-only-not-a-real-signature'))).join('.')

const tokenType = 'urn:ietf:params:oauth:token-type:access_token'
export const grants = ['authorization_code', 'client_credentials', 'refresh_token', 'device_code', 'password', 'token_exchange']

function required(value, field) {
  if (typeof value !== 'string' || !value.trim()) throw new ToolError('required', field)
  return value
}

function endpoint(value, field) {
  required(value, field)
  let url
  try { url = new URL(value) } catch { throw new ToolError('url', field) }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || /[\s#\u0000-\u001f\u007f]/.test(value)) {
    throw new ToolError('url', field)
  }
  // Avoid duplicate protocol parameters and accidental credentials in endpoint URLs.
  if (url.search) throw new ToolError('query', field)
  return url.href
}

function redirect(value) {
  required(value, 'redirectUri')
  let url
  try { url = new URL(value) } catch { throw new ToolError('redirect', 'redirectUri') }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || /[\s#\u0000-\u001f\u007f]/.test(value)) {
    throw new ToolError('redirect', 'redirectUri')
  }
  // Preserve the exact registered string, including its query and trailing slash.
  return value
}

function quote(value) {
  return `'${value.replace(/'/g, `'"'"'`)}'`
}

function formEncode(value) {
  return new URLSearchParams({ value }).toString().slice('value='.length)
}

function post(label, url, fields, clientId, auth) {
  const args = ['curl --request POST', `  --url ${quote(url)}`]
  if (auth === 'client_secret_basic') {
    // RFC 6749 §2.3.1: encode each credential before HTTP Basic encoding.
    args.push(`  --user ${quote(`${formEncode(clientId)}:REPLACE_WITH_CLIENT_SECRET`)}`)
  } else {
    fields.unshift(['client_id', clientId])
  }
  args.push("  --header 'Content-Type: application/x-www-form-urlencoded'")
  for (const [key, value] of fields) args.push(`  --data-urlencode ${quote(`${key}=${value}`)}`)
  return { label, method: 'POST', text: args.join(' \\\n') }
}

export async function buildRequests(options, crypto = globalThis.crypto) {
  const { grant, clientId, auth, scope = '' } = options
  if (!grants.includes(grant)) throw new ToolError('grant')
  required(clientId, 'clientId')
  if (!['none', 'client_secret_basic'].includes(auth) || (auth === 'none' && !['authorization_code', 'device_code'].includes(grant))) {
    throw new ToolError('auth')
  }
  const tokenUrl = endpoint(options.tokenEndpoint, 'tokenEndpoint')
  const scopes = scope.trim() ? [['scope', scope.trim()]] : []
  const token = (fields, label = 'token') => post(label, tokenUrl, fields, clientId, auth)

  if (grant === 'authorization_code') {
    const url = new URL(endpoint(options.authorizationEndpoint, 'authorizationEndpoint'))
    const redirectUri = redirect(options.redirectUri)
    const verifier = randomValue(crypto)
    const challenge = await s256(verifier, crypto)
    const params = new URLSearchParams([
      ['response_type', 'code'], ['client_id', clientId], ['redirect_uri', redirectUri], ...scopes,
      ['state', randomValue(crypto)], ['code_challenge', challenge], ['code_challenge_method', 'S256']
    ])
    if (scope.trim().split(/\s+/).includes('openid')) params.set('nonce', randomValue(crypto))
    url.search = params.toString()
    return [
      { label: 'verifier', method: 'S256', text: verifier },
      { label: 'authorization', method: 'GET', text: url.href },
      token([['grant_type', grant], ['code', 'REPLACE_WITH_AUTHORIZATION_CODE'], ['redirect_uri', redirectUri], ['code_verifier', verifier]])
    ]
  }
  if (grant === 'device_code') {
    return [
      post('device', endpoint(options.deviceEndpoint, 'deviceEndpoint'), [...scopes], clientId, auth),
      token([['grant_type', 'urn:ietf:params:oauth:grant-type:device_code'], ['device_code', 'REPLACE_WITH_DEVICE_CODE']], 'poll')
    ]
  }
  const fields = grant === 'client_credentials' ? [['grant_type', grant]]
    : grant === 'refresh_token' ? [['grant_type', grant], ['refresh_token', 'REPLACE_WITH_REFRESH_TOKEN']]
    : grant === 'password' ? [['grant_type', grant], ['username', 'REPLACE_WITH_USERNAME'], ['password', 'REPLACE_WITH_PASSWORD']]
    : [['grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange'], ['subject_token', 'REPLACE_WITH_SUBJECT_TOKEN'], ['subject_token_type', tokenType], ['requested_token_type', tokenType]]
  return [token([...fields, ...scopes])]
}

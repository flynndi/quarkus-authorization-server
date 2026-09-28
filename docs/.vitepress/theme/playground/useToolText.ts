import { useData } from 'vitepress'
import { ToolError } from './oauth-tools.mjs'

export function useToolText() {
  const { lang } = useData()
  const t = (en: string, zh: string) => lang.value.startsWith('zh') ? zh : en
  const errors: Record<string, [string, string]> = {
    crypto: ['Web Crypto is unavailable. Open this page over HTTPS or localhost.', 'Web Crypto 不可用，请通过 HTTPS 或 localhost 打开页面。'],
    verifier: ['Use 43–128 characters: letters, digits, or - . _ ~. Spaces are not allowed.', 'verifier 需为 43–128 位字母、数字或 - . _ ~，不能包含空格。'],
    base64: ['A segment is not valid, unpadded base64url.', '分段不是有效的无填充 base64url 编码。'],
    json: ['Header and payload must each decode to a UTF-8 JSON object.', 'Header 和 Payload 必须分别解码为 UTF-8 JSON 对象。'],
    segments: ['Paste a compact JWT with three dot-separated segments, without the Bearer prefix.', '请粘贴由点分隔的三段式 JWT，不要包含 Bearer 前缀。'],
    encrypted: ['This is a five-part JWE. This tool cannot decrypt it.', '这是五段式 JWE，本工具不提供解密。'],
    unencoded: ['Unencoded JWS payloads are not supported by this JWT decoder.', '本 JWT 解码器不支持未编码的 JWS Payload。'],
    size: ['Use a token no larger than 64 KiB of text.', 'Token 文本不能超过 64 KiB。'],
    required: ['This field is required.', '此字段不能为空。'],
    url: ['Use an absolute HTTP(S) endpoint without credentials or a fragment.', '请填写完整的 HTTP(S) 端点，不包含用户名、密码或片段标识。'],
    query: ['Use an endpoint without query parameters. This tool supplies the protocol parameters.', '端点不能包含查询参数，协议参数由工具构造。'],
    redirect: ['Use an absolute HTTP(S) redirect URI without credentials or a fragment.', '请填写完整的 HTTP(S) 回调 URI，不包含用户名、密码或片段标识。'],
    auth: ['This example requires client_secret_basic authentication.', '此示例需要 client_secret_basic 客户端认证。'],
    grant: ['Choose a supported grant.', '请选择支持的授权模式。']
  }
  const errorText = (error: unknown) => {
    const pair = error instanceof ToolError ? errors[error.code] : undefined
    return pair ? t(...pair) : t('The operation failed. Please try again.', '操作失败，请重试。')
  }
  return { t, errorText }
}

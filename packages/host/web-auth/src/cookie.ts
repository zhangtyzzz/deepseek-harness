/**
 * Sign-in cookie encoding for the web-authentication seam: the one place the
 * browser-facing security attributes of the session cookie are decided.
 *
 * Every issued cookie carries `HttpOnly` (script must never read the token),
 * `SameSite=Strict`, and `Path=/`. `SameSite=Strict` is what lets an
 * authenticated request satisfy the `/api` trust fence: a cross-site context —
 * including a DNS-rebound page, which is a different site than the authority
 * the cookie was issued for — never has the cookie attached, so possession of
 * it evidences a first-party context rather than merely a reachable socket.
 * @module @deepseek-ai/dsh-host-web-auth/cookie
 */

import type { IncomingHttpHeaders } from 'node:http'

/** Cookie carrying the sign-in session token. */
export const SESSION_COOKIE_NAME = 'dsh_web_auth'

/**
 * When to mark the cookie `Secure`. A harness serves plain HTTP even when the
 * browser reached it over HTTPS through a tunnel or reverse proxy, so the
 * correct answer is a deployment fact rather than something the process can
 * observe from its own socket.
 */
export type CookieSecurePolicy =
  /** Mark `Secure` only when the request reports an HTTPS forwarding hop. */
  | 'auto'
  /** Always mark `Secure`; correct whenever every route to the harness is HTTPS. */
  | 'always'
  /** Never mark `Secure`; required for a plain-HTTP LAN deployment. */
  | 'never'

/**
 * Read one header from either HTTP representation, ignoring the repeated-header
 * array form: no header this seam reads is legitimately repeated.
 * @param headers - the request's headers in either representation.
 * @param name - lowercase header name.
 * @returns the single header value, or undefined.
 */
export function header(headers: IncomingHttpHeaders | Headers, name: string): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  const value = headers[name]
  return typeof value === 'string' ? value : undefined
}

/**
 * Whether an issued cookie should be marked `Secure` under this policy.
 * `auto` trusts `x-forwarded-proto` only to ADD the attribute: a client that
 * omits or rewrites the header can weaken nothing but its own cookie, while a
 * deployment that wants the guarantee unconditionally sets `always`.
 * @param policy - the configured policy.
 * @param headers - headers of the request being answered.
 * @returns true when `Secure` belongs on the cookie.
 */
export function isSecureCookieRequest(policy: CookieSecurePolicy, headers: IncomingHttpHeaders | Headers): boolean {
  if (policy !== 'auto') return policy === 'always'
  // A proxy chain reports the ORIGINAL scheme first; later hops are internal.
  const forwarded = header(headers, 'x-forwarded-proto')?.split(',', 1)[0]?.trim().toLowerCase()
  return forwarded === 'https'
}

function serialize(value: string, maxAgeSeconds: number, secure: boolean): string {
  return [
    `${SESSION_COOKIE_NAME}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${String(maxAgeSeconds)}`,
    ...secure ? ['Secure'] : [],
  ].join('; ')
}

/**
 * `Set-Cookie` value establishing a sign-in session.
 * @param token - the opaque session token.
 * @param maxAgeSeconds - cookie lifetime, matching the server-side record's.
 * @param secure - whether to mark the cookie `Secure`.
 * @returns the header value.
 */
export function sessionCookie(token: string, maxAgeSeconds: number, secure: boolean): string {
  return serialize(token, maxAgeSeconds, secure)
}

/**
 * `Set-Cookie` value clearing the sign-in session. The attributes must match
 * the issued cookie or the browser keeps the original pair alongside this one.
 * @param secure - whether the issued cookie was marked `Secure`.
 * @returns the header value.
 */
export function clearedSessionCookie(secure: boolean): string {
  return serialize('', 0, secure)
}

/**
 * Read one cookie value from a request's `Cookie` header.
 * @param headers - the request's headers in either representation.
 * @param name - the cookie name, compared exactly.
 * @returns the value, or undefined when the cookie is absent or empty.
 */
export function readCookie(headers: IncomingHttpHeaders | Headers, name: string): string | undefined {
  const cookies = header(headers, 'cookie')
  if (cookies === undefined) return undefined
  for (const pair of cookies.split(';')) {
    const separator = pair.indexOf('=')
    if (separator === -1) continue
    if (pair.slice(0, separator).trim() !== name) continue
    const value = pair.slice(separator + 1).trim()
    return value === '' ? undefined : value
  }
  return undefined
}

/**
 * Read the sign-in token from a request's `Cookie` header.
 * @param headers - the request's headers in either representation.
 * @returns the token, or undefined when the cookie is absent or empty.
 */
export function readSessionToken(headers: IncomingHttpHeaders | Headers): string | undefined {
  return readCookie(headers, SESSION_COOKIE_NAME)
}

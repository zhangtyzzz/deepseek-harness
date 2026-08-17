/**
 * The Cloudflare Access provider: verifies the token the edge forwards on every
 * request and reports the authenticated user.
 * @module @deepseek-ai/dsh-host-web-auth-cloudflare-access/provider
 */

import {
  readCookie,
  readHeader,
  type WebAuthIdentity,
  type WebAuthProvider,
  type WebAuthRequest,
} from '@deepseek-ai/dsh-host-web-auth'
import { JwksCache } from './jwks.ts'
import { tokenKeyId, TokenError, verifyToken } from './jwt.ts'

/** Registry id this provider claims. */
export const CLOUDFLARE_ACCESS_PROVIDER_ID = 'cloudflare-access'

/** Header Cloudflare Access sets on every proxied request. */
const ASSERTION_HEADER = 'cf-access-jwt-assertion'

/** Cookie Cloudflare Access sets in the browser, used when the header is absent. */
const ASSERTION_COOKIE = 'CF_Authorization'

/** Options for {@link CloudflareAccessProvider}. */
export interface CloudflareAccessProviderOptions {
  /** Expected token issuer: the team domain's `https://` origin. */
  readonly issuer: string
  /** Expected Access application Audience (AUD) tag. */
  readonly audience: string
  /** Signing key-set endpoint. */
  readonly certsUrl: string
  /**
   * Called with the reason a presented token did not verify. A rejected token
   * is reported here rather than to the caller, who only ever learns the
   * request was unauthenticated.
   */
  readonly onRejected?: (reason: string) => void
  /** Millisecond clock; injectable so token expiry and key caching are testable. */
  readonly now?: () => number
}

/** Cloudflare Access token verification against the team's rotating key set. */
export class CloudflareAccessProvider implements WebAuthProvider {
  readonly id = CLOUDFLARE_ACCESS_PROVIDER_ID

  private readonly keys: JwksCache
  private readonly now: () => number

  /**
   * @param options - issuer, audience, key-set endpoint, and reporting hooks.
   */
  constructor(private readonly options: CloudflareAccessProviderOptions) {
    this.now = options.now ?? Date.now
    this.keys = new JwksCache(options.certsUrl, this.now)
  }

  /**
   * Verify the Access token this request carries.
   * @param request - the request's headers.
   * @returns the authenticated user, or undefined when no valid token is present.
   */
  async verifyRequest(request: WebAuthRequest): Promise<WebAuthIdentity | undefined> {
    const token = readHeader(request.headers, ASSERTION_HEADER)
      ?? readCookie(request.headers, ASSERTION_COOKIE)
    if (token === undefined) return undefined
    try {
      const kid = tokenKeyId(token)
      const key = await this.keys.resolve(kid)
      if (key === undefined) {
        this.options.onRejected?.(`no signing key for kid ${JSON.stringify(kid)}`)
        return undefined
      }
      const verified = verifyToken(
        token,
        key,
        this.options.audience,
        this.options.issuer,
        Math.floor(this.now() / 1000),
      )
      return { provider: this.id, subject: verified.subject }
    } catch (error) {
      // A malformed or forged token is an ordinary unauthenticated request; a
      // key-set fetch failure is reported the same way rather than failing the
      // request, so an outage at the edge cannot be turned into a 500 oracle.
      this.options.onRejected?.(error instanceof TokenError ? error.message : String(error))
      return undefined
    }
  }
}

/**
 * `@deepseek-ai/dsh-host-web-auth` — Service Definition for the web-access
 * authentication seam (`ctx.webAuth`): the provider registry, the sign-in
 * session lifecycle, and the cookie encoding shared by every provider.
 *
 * The seam is transport-agnostic on purpose. It decides WHETHER a request
 * carries a verified principal and mints or revokes the browser session that
 * records one; it registers no route and reads no `Host`. The Consumer that
 * already owns the browser-authority fence — `@deepseek-ai/dsh-client-connection`
 * — mounts the sign-in surface behind that fence and enforces the requirement
 * on `/api`, so which authorities a deployment answers to stays one fact in one
 * place.
 *
 * Mounting this service with at least one provider makes authentication
 * REQUIRED for non-loopback access. A composition with no provider row leaves
 * the harness exactly as it was: loopback-only serving, `trustedHosts` as the
 * sole rebinding fence, and the configuration plane pinned to loopback.
 * @module @deepseek-ai/dsh-host-web-auth
 */

import { Context, Service } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import {
  clearedSessionCookie,
  isSecureCookieRequest,
  readSessionToken,
  sessionCookie,
  type CookieSecurePolicy,
} from './cookie.ts'
import { SignInSessions } from './sessions.ts'
import type { WebAuthClient, WebAuthIdentity, WebAuthProvider, WebAuthRequest } from './types.ts'

export { AUTH_PATH, LOGIN_PATH, SIGN_IN_PATH, SIGN_OUT_PATH, STATUS_PATH } from './paths.ts'
export { LOGIN_PAGE_HTML } from './login-page.ts'
// Request-reading helpers every `verifyRequest` provider needs; they keep the
// two accepted header representations handled in one place.
export { header as readHeader, readCookie, SESSION_COOKIE_NAME } from './cookie.ts'
export type { CookieSecurePolicy } from './cookie.ts'
export type {
  WebAuthClient,
  WebAuthIdentity,
  WebAuthProvider,
  WebAuthRequest,
  WebAuthSignInOutcome,
} from './types.ts'

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** Web-access authentication: provider registry and sign-in session lifecycle. */
    webAuth: WebAuth
  }
}

/** Config for the authentication seam. */
export interface WebAuthConfig {
  /**
   * Lifetime of a browser sign-in session. A signed-in browser is re-prompted
   * after this long, and the record is dropped server-side at the same moment.
   */
  sessionTtlSeconds?: number
  /**
   * Whether issued cookies are marked `Secure`. A harness serves plain HTTP
   * even when the browser reached it over HTTPS through a tunnel, so this is a
   * deployment fact: `auto` marks `Secure` when the request reports an HTTPS
   * forwarding hop, `always` suits a deployment reachable only over HTTPS, and
   * `never` is required for plain-HTTP LAN serving.
   */
  cookieSecure?: CookieSecurePolicy
}

/** Schema defaults, restated for hand-built contexts that pass a partial config. */
const DEFAULT_SESSION_TTL_SECONDS = 12 * 60 * 60
const DEFAULT_COOKIE_SECURE: CookieSecurePolicy = 'auto'

export const Config: z<WebAuthConfig> = z.object({
  sessionTtlSeconds: z.natural().min(60).default(DEFAULT_SESSION_TTL_SECONDS),
  cookieSecure: z.union([z.const('auto'), z.const('always'), z.const('never')] as const).default(DEFAULT_COOKIE_SECURE),
})

/** Why a sign-in attempt did not produce a session. */
export type SignInFailure =
  /** No mounted provider verifies submitted secrets, so sign-in cannot succeed here. */
  | { readonly outcome: 'unsupported' }
  /** Every provider that judged the secret rejected it. */
  | { readonly outcome: 'rejected' }
  /** A provider is rate-limiting this client. */
  | { readonly outcome: 'locked'; readonly retryAfterSeconds: number }

/** Result of a sign-in attempt. */
export type SignInResult =
  | {
    readonly outcome: 'verified'
    readonly identity: WebAuthIdentity
    /** `Set-Cookie` value establishing the browser session. */
    readonly setCookie: string
  }
  | SignInFailure

/** What a caller may learn about the authentication state without being signed in. */
export interface WebAuthStatus {
  /** Whether non-loopback access requires authentication in this composition. */
  readonly required: boolean
  /** Whether THIS request already carries a verified principal. */
  readonly authenticated: boolean
  /** Whether a mounted provider accepts a submitted secret, i.e. whether the sign-in page can work. */
  readonly interactive: boolean
}

/**
 * The authentication service. Providers register into it; the browser-transport
 * Consumer reads it to decide whether a request may pass the `/api` fence.
 *
 * Verification order is deliberate and not registration-dependent: an existing
 * sign-in session is honored first (one map lookup, no provider work), then
 * each provider's per-request credential check runs until one verifies. Only
 * request-credential providers participate there, so adding an interactive
 * provider never adds per-request cost.
 */
export class WebAuth extends Service {
  static Config = Config

  private readonly providers = new Map<string, WebAuthProvider>()
  private readonly sessions: SignInSessions
  private readonly ttlSeconds: number
  private readonly cookieSecure: CookieSecurePolicy

  /**
   * @param ctx - owning plugin context.
   * @param config - resolved seam config; the Loader applies schema defaults,
   * and a hand-built context may pass a partial record.
   */
  constructor(ctx: Context, config?: WebAuthConfig) {
    super(ctx, 'webAuth')
    this.ttlSeconds = config?.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS
    this.cookieSecure = config?.cookieSecure ?? DEFAULT_COOKIE_SECURE
    this.sessions = new SignInSessions(this.ttlSeconds)
    // Sessions are process-local, so a disposed seam must not leave live
    // principals resolvable through a re-mounted one.
    ctx.effect(() => () => { this.sessions.clear() }, 'web-auth: sign-in sessions')
  }

  /**
   * Register one authentication provider. Disposed with the calling fiber.
   * @param provider - the mechanism; its `id` is the registry key.
   * @returns the disposer that unregisters it.
   * @throws when the id is already registered, or when the provider supplies
   * neither verification surface — such a provider could never authenticate
   * anything while still making authentication REQUIRED, locking the
   * deployment out of its own harness.
   */
  register(provider: WebAuthProvider): () => void {
    if (provider.verifyRequest === undefined && provider.verifySecret === undefined) {
      throw new Error(`web-auth: provider ${JSON.stringify(provider.id)} supplies no verification surface`)
    }
    if (this.providers.has(provider.id)) {
      throw new Error(`web-auth: a provider with id ${JSON.stringify(provider.id)} is already registered`)
    }
    const providers = this.providers
    const dispose = this.ctx.effect(function* (this: void) {
      providers.set(provider.id, provider)
      yield () => providers.delete(provider.id)
    }, `web-auth: ${provider.id} provider`)
    // ctx.effect's disposer returns Promise<void>; this registry's disposer is
    // synchronous fire-and-forget — discard the (always-resolved) promise.
    return () => void dispose()
  }

  /**
   * Whether this composition requires authentication for non-loopback access.
   * False while no provider is mounted, which is what keeps a seam row that a
   * deployment mounted without any provider from silently gating nothing:
   * the requirement follows the providers, not the row.
   */
  get required(): boolean {
    return this.providers.size > 0
  }

  /** Whether a mounted provider can verify a submitted secret. */
  get interactive(): boolean {
    return [...this.providers.values()].some(provider => provider.verifySecret !== undefined)
  }

  /**
   * Resolve the verified principal behind one request.
   * @param request - the request's headers.
   * @returns the principal, or undefined when the request carries none.
   */
  async authenticate(request: WebAuthRequest): Promise<WebAuthIdentity | undefined> {
    const token = readSessionToken(request.headers)
    if (token !== undefined) {
      const identity = this.sessions.resolve(token)
      if (identity !== undefined) return identity
    }
    for (const provider of this.providers.values()) {
      const identity = await provider.verifyRequest?.(request)
      if (identity !== undefined) return identity
    }
    return undefined
  }

  /**
   * Report the authentication state for one request.
   * @param request - the request's headers.
   * @returns what the caller may know before signing in.
   */
  async status(request: WebAuthRequest): Promise<WebAuthStatus> {
    return {
      required: this.required,
      authenticated: await this.authenticate(request) !== undefined,
      interactive: this.interactive,
    }
  }

  /**
   * Verify a submitted secret and, on success, mint a browser session.
   *
   * A provider reporting a lockout ends the attempt immediately rather than
   * letting the secret fall through to the next provider, so a second mounted
   * provider can never be used to side-step the first one's rate limit.
   * @param secret - the submitted secret, verbatim.
   * @param client - where the attempt came from, for provider rate limiting.
   * @param request - the request's headers, read for the cookie's `Secure` decision.
   * @returns the minted session, or why no session was minted.
   */
  async signIn(secret: string, client: WebAuthClient, request: WebAuthRequest): Promise<SignInResult> {
    let judged = false
    for (const provider of this.providers.values()) {
      if (provider.verifySecret === undefined) continue
      judged = true
      const verdict = await provider.verifySecret(secret, client)
      if (verdict.outcome === 'locked') return verdict
      if (verdict.outcome === 'rejected') continue
      return {
        outcome: 'verified',
        identity: verdict.identity,
        setCookie: sessionCookie(
          this.sessions.issue(verdict.identity),
          this.ttlSeconds,
          isSecureCookieRequest(this.cookieSecure, request.headers),
        ),
      }
    }
    return judged ? { outcome: 'rejected' } : { outcome: 'unsupported' }
  }

  /**
   * Revoke the sign-in session a request presents.
   * @param request - the request's headers.
   * @returns the `Set-Cookie` value clearing the browser's cookie. Emitted even
   * when no live session matched, so a stale cookie is always cleared.
   */
  signOut(request: WebAuthRequest): { setCookie: string } {
    const token = readSessionToken(request.headers)
    if (token !== undefined) this.sessions.revoke(token)
    return { setCookie: clearedSessionCookie(isSecureCookieRequest(this.cookieSecure, request.headers)) }
  }
}

export default WebAuth

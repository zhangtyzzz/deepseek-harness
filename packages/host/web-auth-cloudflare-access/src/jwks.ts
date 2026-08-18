/**
 * Cached public keys for Cloudflare Access token verification.
 *
 * Cloudflare rotates signing keys, so keys are fetched rather than configured,
 * and a token naming an unknown `kid` triggers at most one refetch per cooldown
 * window — otherwise an attacker could turn a stream of forged key ids into
 * unbounded outbound requests. Concurrent callers share one in-flight fetch.
 * @module @deepseek-ai/dsh-host-web-auth-cloudflare-access/jwks
 */

import type { JsonWebKey } from 'node:crypto'

/** How long a successful key set is served before a scheduled refresh. */
const KEY_SET_TTL_MS = 60 * 60 * 1000

/** Floor between fetches triggered by an unknown key id. */
const UNKNOWN_KID_COOLDOWN_MS = 60 * 1000

/** Timeout for one key-set fetch; a hung endpoint must not stall request verification. */
const FETCH_TIMEOUT_MS = 5_000

/** Cloudflare's certs document, reduced to what verification needs. */
interface KeySetDocument {
  readonly keys?: readonly (JsonWebKey & { readonly kid?: unknown })[]
}

/** Public-key lookup over a cached remote key set. */
export class JwksCache {
  private keys = new Map<string, JsonWebKey>()
  private fetchedAt = 0
  private inFlight: Promise<void> | undefined

  /**
   * @param url - the key-set endpoint.
   * @param now - millisecond clock; injectable so cooldown and TTL are testable.
   */
  constructor(private readonly url: string, private readonly now: () => number = Date.now) {}

  /**
   * Resolve the key a token names, fetching or refreshing when needed.
   * @param kid - key id from the token header, or undefined when it named none.
   * @returns the matching JWK, or undefined when the key set does not contain it.
   */
  async resolve(kid: string | undefined): Promise<JsonWebKey | undefined> {
    const age = this.now() - this.fetchedAt
    if (this.keys.size === 0 || age >= KEY_SET_TTL_MS) await this.refresh()
    if (kid === undefined) {
      // A key set with exactly one key identifies itself; more than one is
      // ambiguous and the token must say which.
      return this.keys.size === 1 ? [...this.keys.values()][0] : undefined
    }
    const known = this.keys.get(kid)
    if (known !== undefined) return known
    // Unknown kid: a rotation may have just happened, so refetch — but only
    // once per cooldown, so forged key ids cannot drive outbound traffic.
    if (this.now() - this.fetchedAt < UNKNOWN_KID_COOLDOWN_MS) return undefined
    await this.refresh()
    return this.keys.get(kid)
  }

  /** Fetch the key set, coalescing concurrent callers onto one request. */
  private async refresh(): Promise<void> {
    this.inFlight ??= this.fetchKeys().finally(() => { this.inFlight = undefined })
    await this.inFlight
  }

  private async fetchKeys(): Promise<void> {
    const response = await fetch(this.url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { accept: 'application/json' },
    })
    if (!response.ok) {
      throw new Error(`web-auth-cloudflare-access: key set ${this.url} answered ${String(response.status)}`)
    }
    const document = await response.json() as KeySetDocument
    const fetched = new Map<string, JsonWebKey>()
    for (const key of document.keys ?? []) {
      if (typeof key.kid === 'string') fetched.set(key.kid, key)
    }
    if (fetched.size === 0) {
      throw new Error(`web-auth-cloudflare-access: key set ${this.url} carries no usable keys`)
    }
    // Replace wholesale: a key Cloudflare withdrew must stop verifying tokens.
    this.keys = fetched
    this.fetchedAt = this.now()
  }
}

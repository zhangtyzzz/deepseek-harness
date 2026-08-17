/**
 * Server-side sign-in session records for the web-authentication seam.
 *
 * Tokens are high-entropy random values kept only as SHA-256 digests, so a
 * memory disclosure of this table does not yield usable cookies, and sign-out
 * revokes for real instead of waiting out a self-describing token's expiry.
 * Records are process-local: restarting the harness invalidates every browser
 * session, which is the intended trade for holding no signing key on disk.
 * @module @deepseek-ai/dsh-host-web-auth/sessions
 */

import { createHash, randomBytes } from 'node:crypto'
import type { WebAuthIdentity } from './types.ts'

/** Token entropy: 256 bits, the same order as the digest that indexes it. */
const TOKEN_BYTES = 32

/**
 * Live-record ceiling. Not a deployment tunable but a memory bound: each
 * successful sign-in adds a record, and a browser that keeps signing in
 * without signing out would otherwise grow this table without limit. The
 * oldest record is evicted first, so an operator's own newest session always
 * survives.
 */
const MAX_LIVE_SESSIONS = 128

interface SessionRecord {
  readonly identity: WebAuthIdentity
  readonly expiresAt: number
}

/** Digest of a token, used as the table key so no raw token is retained. */
function digest(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

/** In-memory sign-in session table with lazy expiry. */
export class SignInSessions {
  /** Insertion-ordered, which is what makes oldest-first eviction a Map walk. */
  private readonly records = new Map<string, SessionRecord>()

  /**
   * @param ttlSeconds - lifetime granted to each issued session.
   * @param now - millisecond clock; injectable so expiry is testable without global timer control.
   */
  constructor(
    private readonly ttlSeconds: number,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * Mint a session for a verified principal.
   * @param identity - the verified principal.
   * @returns the opaque token to place in the cookie; retained only as a digest.
   */
  issue(identity: WebAuthIdentity): string {
    const token = randomBytes(TOKEN_BYTES).toString('base64url')
    if (this.records.size >= MAX_LIVE_SESSIONS) this.evictOldest()
    this.records.set(digest(token), { identity, expiresAt: this.now() + this.ttlSeconds * 1000 })
    return token
  }

  /**
   * Resolve a token presented by a request.
   * @param token - the cookie value.
   * @returns the principal, or undefined when unknown or expired.
   */
  resolve(token: string): WebAuthIdentity | undefined {
    const key = digest(token)
    const record = this.records.get(key)
    if (record === undefined) return undefined
    if (record.expiresAt <= this.now()) {
      this.records.delete(key)
      return undefined
    }
    return record.identity
  }

  /**
   * Revoke a token, if it names a live session.
   * @param token - the cookie value.
   */
  revoke(token: string): void {
    this.records.delete(digest(token))
  }

  /** Drop every record; the seam calls this when its fiber is disposed. */
  clear(): void {
    this.records.clear()
  }

  /** Remove one record: the first expired one, else the least recently issued. */
  private evictOldest(): void {
    const current = this.now()
    let oldestKey: string | undefined
    for (const [key, record] of this.records) {
      if (record.expiresAt <= current) {
        this.records.delete(key)
        return
      }
      oldestKey ??= key
    }
    /* v8 ignore next -- `undefined` arm: eviction runs only at the ceiling, so
    the table is never empty here. */
    if (oldestKey !== undefined) this.records.delete(oldestKey)
  }
}

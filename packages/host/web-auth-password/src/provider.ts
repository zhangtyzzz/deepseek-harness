/**
 * The password provider: verifies a submitted password against the harness's
 * generated credential and rate-limits consecutive failures per client.
 *
 * The lockout is what makes a rate-limited password endpoint safe to expose:
 * the credential carries 125 bits of entropy, so guessing is infeasible once
 * attempts are throttled, and a locked client is reported to the seam as
 * `locked` rather than `rejected` so no second provider can be used to keep
 * guessing.
 * @module @deepseek-ai/dsh-host-web-auth-password/provider
 */

import type { WebAuthClient, WebAuthProvider, WebAuthSignInOutcome } from '@deepseek-ai/dsh-host-web-auth'
import { verifyPassword, type LoadedCredential } from './credential-file.ts'

/** Registry id this provider claims. */
export const PASSWORD_PROVIDER_ID = 'password'

/** Subject recorded for a session established by the harness password. */
export const PASSWORD_SUBJECT = 'local-password'

/**
 * Default tracked-client ceiling. A memory bound rather than a deployment
 * tunable: attempts arrive from caller-chosen addresses, so the table must not
 * grow with them. Eviction drops the entry closest to expiry first, which keeps
 * an in-force lockout while shedding stale counters.
 */
const DEFAULT_MAX_TRACKED_CLIENTS = 1024

/** Key for clients whose address the carrier could not report. */
const UNKNOWN_CLIENT = 'unknown'

interface AttemptRecord {
  failures: number
  /** Epoch milliseconds until which this client is refused, or 0 when not locked. */
  lockedUntil: number
}

/** Options for {@link PasswordAuthProvider}. */
export interface PasswordAuthProviderOptions {
  /** The loaded credential this provider verifies against. */
  readonly credential: LoadedCredential['credential']
  /** Consecutive failures from one client that trigger a lockout. */
  readonly maxAttempts: number
  /** How long a triggered lockout refuses that client. */
  readonly lockoutSeconds: number
  /**
   * Live failure-counter ceiling; defaults to
   * {@link DEFAULT_MAX_TRACKED_CLIENTS}. The plugin does not expose it — it
   * bounds memory, not policy.
   */
  readonly maxTrackedClients?: number
  /** Millisecond clock; injectable so lockout expiry is testable without global timer control. */
  readonly now?: () => number
}

/** Password verification with per-client failure lockout. */
export class PasswordAuthProvider implements WebAuthProvider {
  readonly id = PASSWORD_PROVIDER_ID

  private readonly attempts = new Map<string, AttemptRecord>()
  private readonly now: () => number
  private readonly maxTrackedClients: number

  /**
   * @param options - credential and lockout policy.
   */
  constructor(private readonly options: PasswordAuthProviderOptions) {
    this.now = options.now ?? Date.now
    this.maxTrackedClients = options.maxTrackedClients ?? DEFAULT_MAX_TRACKED_CLIENTS
  }

  /**
   * Verify a submitted password, applying the per-client lockout.
   * @param secret - the submitted password, verbatim.
   * @param client - where the attempt came from; the lockout keys on its address.
   * @returns the seam's sign-in verdict.
   */
  async verifySecret(secret: string, client: WebAuthClient): Promise<WebAuthSignInOutcome> {
    const key = client.address ?? UNKNOWN_CLIENT
    const current = this.now()
    const record = this.attempts.get(key)
    if (record !== undefined && record.lockedUntil > current) {
      return {
        outcome: 'locked',
        retryAfterSeconds: Math.ceil((record.lockedUntil - current) / 1000),
      }
    }
    // Verify before recording: a correct password from a client whose previous
    // lockout has just expired must succeed on its first attempt.
    if (await verifyPassword(secret, this.options.credential)) {
      this.attempts.delete(key)
      return { outcome: 'verified', identity: { provider: this.id, subject: PASSWORD_SUBJECT } }
    }
    this.recordFailure(key, record, current)
    return { outcome: 'rejected' }
  }

  private recordFailure(key: string, existing: AttemptRecord | undefined, current: number): void {
    let record = existing
    if (record === undefined) {
      if (this.attempts.size >= this.maxTrackedClients) this.evictOne(current)
      record = { failures: 0, lockedUntil: 0 }
      this.attempts.set(key, record)
    }
    // A lockout that has expired starts the client's count over, so the
    // threshold always describes CONSECUTIVE failures within one window. A
    // fresh record enters at zero, so the threshold applies to a client's very
    // first failure too — `maxAttempts: 1` locks immediately.
    record.failures = record.lockedUntil > 0 ? 1 : record.failures + 1
    record.lockedUntil = record.failures >= this.options.maxAttempts
      ? current + this.options.lockoutSeconds * 1000
      : 0
  }

  /** Drop the tracked client closest to expiry, so live lockouts outlive stale counters. */
  private evictOne(current: number): void {
    let weakestKey: string | undefined
    let weakestUntil = Number.POSITIVE_INFINITY
    for (const [key, record] of this.attempts) {
      if (record.lockedUntil <= current) {
        this.attempts.delete(key)
        return
      }
      if (record.lockedUntil < weakestUntil) {
        weakestUntil = record.lockedUntil
        weakestKey = key
      }
    }
    /* v8 ignore next -- `undefined` arm: eviction runs only at the ceiling, so
    the table is never empty here. */
    if (weakestKey !== undefined) this.attempts.delete(weakestKey)
  }
}

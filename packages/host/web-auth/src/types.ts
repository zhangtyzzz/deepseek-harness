/**
 * Vocabulary of the web-authentication seam: what a provider verifies, what a
 * verified principal is, and the two verification surfaces a provider may
 * supply.
 * @module @deepseek-ai/dsh-host-web-auth/types
 */

import type { IncomingHttpHeaders } from 'node:http'

/** A principal one provider has verified for the current request. */
export interface WebAuthIdentity {
  /** Registry id of the provider that verified this principal. */
  readonly provider: string
  /**
   * Label naming who was verified, for the sign-in session record and
   * diagnostics. Providers that authenticate a deployment secret rather than a
   * person use a fixed label; the seam never parses it.
   */
  readonly subject: string
}

/**
 * The request facts a provider may read. Both HTTP representations the host
 * serves are accepted, matching the trust fence's own request type: the
 * `node:http` route handlers and the Fetch handlers the `/api` bridge builds.
 */
export interface WebAuthRequest {
  readonly headers: IncomingHttpHeaders | Headers
}

/** Where a sign-in attempt came from, for provider-owned rate limiting. */
export interface WebAuthClient {
  /**
   * Remote peer address of the submitting socket, or undefined when the
   * carrier could not report one. Behind a reverse proxy every attempt shares
   * the proxy's address, so a provider keying a lockout on this value limits
   * the proxy as one client.
   */
  readonly address?: string
}

/** Outcome of verifying a secret submitted through the seam's sign-in endpoint. */
export type WebAuthSignInOutcome =
  /** The secret is this provider's and correct. */
  | { readonly outcome: 'verified'; readonly identity: WebAuthIdentity }
  /** The secret is this provider's and wrong. */
  | { readonly outcome: 'rejected' }
  /**
   * This provider refuses to judge further attempts from this client for now.
   * The seam reports the wait to the caller and never falls through to another
   * provider, so one provider's lockout cannot be side-stepped.
   */
  | { readonly outcome: 'locked'; readonly retryAfterSeconds: number }

/**
 * One authentication mechanism. A provider supplies at least one verification
 * surface; the seam asserts that at registration, because a provider with
 * neither could never authenticate anything and would silently weaken a
 * deployment that believed it had mounted authentication.
 */
export interface WebAuthProvider {
  /** Registry key; duplicates are refused. */
  readonly id: string
  /**
   * Verify a credential this request carries on its own — a tunnel's signed
   * assertion header, for example. Called on every request the fence gates, so
   * implementations must be cheap and must not block on the network per call.
   * @param request - the request's headers.
   * @returns the verified principal, or undefined when the request carries no
   * credential this provider owns or the credential does not verify.
   */
  verifyRequest?(request: WebAuthRequest): Promise<WebAuthIdentity | undefined>
  /**
   * Verify a secret submitted to the seam's sign-in endpoint. Providers
   * implementing this get a browser sign-in session cookie on success.
   * @param secret - the submitted secret, verbatim.
   * @param client - where the attempt came from, for rate limiting.
   * @returns whether the secret verified, was wrong, or is currently locked out.
   */
  verifySecret?(secret: string, client: WebAuthClient): Promise<WebAuthSignInOutcome>
}

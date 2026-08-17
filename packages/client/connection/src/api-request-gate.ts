/**
 * The admission decision for every gated request on this carrier: the existing
 * browser-authority fence, plus the authentication requirement a mounted
 * `webAuth` seam adds.
 *
 * Authentication is layered ON the authority fence, never substituted for it. A
 * request must still present a `Host` this deployment serves — that check is the
 * DNS-rebinding defense and it is unchanged — and, once a provider is mounted,
 * must additionally carry a verified principal unless it arrived over loopback.
 * The two consequences are deliberate:
 *
 * - A deployment that adds authentication still declares the authorities it
 *   answers to. Serving `dsh.example.com` needs that name in `trustedHosts`
 *   whether or not a provider is mounted.
 * - Loopback keeps reaching everything. That preserves the behavior of every
 *   composition mounting no provider, and loopback access already implies the
 *   ability to run code as this process, so requiring a password of it would
 *   protect nothing.
 *
 * The `loopback` authority — the configuration plane, native dialogs, the
 * methods pinned because `trustedHosts` is not authentication — opens to a
 * verified principal. That is precisely the condition its pin was waiting for.
 * @module @deepseek-ai/dsh-client-connection/api-request-gate
 */

import type { IncomingHttpHeaders } from 'node:http'
import type { ConnectionRpcAuthority } from './rpc.ts'
import { isTrustedApiRequest } from './api-request-trust.ts'

/** The request facts admission reads. */
interface GatedRequest {
  headers: IncomingHttpHeaders | Headers
}

/**
 * The part of the `webAuth` seam this carrier consumes. Structural so the
 * fence's own tests need no service instance, and so the optional dependency
 * stays one narrow reader.
 */
export interface WebAuthGate {
  /** Whether a provider is mounted, i.e. whether authentication is required at all. */
  readonly required: boolean
  /**
   * Resolve the verified principal behind one request.
   * @param request - the request's headers.
   * @returns the principal, or undefined when the request carries none.
   */
  authenticate(request: GatedRequest): Promise<{ readonly subject: string } | undefined>
}

/**
 * Decide whether one request may reach its handler.
 * @param request - Node HTTP or Fetch request facts (headers).
 * @param authority - the channel's declared fence: `loopback` pins to the host
 * machine absent authentication, `trusted-host` accepts declared authorities.
 * @param trustedHosts - non-loopback authorities this deployment serves.
 * @param auth - the mounted authentication seam, or undefined when none is.
 * @returns true when the request is admitted.
 */
export async function admitsRequest(
  request: GatedRequest,
  authority: ConnectionRpcAuthority,
  trustedHosts: readonly string[],
  auth: WebAuthGate | undefined,
): Promise<boolean> {
  const fromLoopback = isTrustedApiRequest(request, [])
  if (authority === 'loopback') {
    if (fromLoopback) return true
    // Absent authentication this is where the request stops, exactly as before.
    if (auth?.required !== true) return false
    return isTrustedApiRequest(request, trustedHosts) && await auth.authenticate(request) !== undefined
  }
  if (!isTrustedApiRequest(request, trustedHosts)) return false
  if (auth?.required !== true) return true
  return fromLoopback || await auth.authenticate(request) !== undefined
}

/**
 * Verification of a Cloudflare Access application token: an RS256 JWT whose
 * signature, audience, issuer, and validity window must all hold before the
 * bearer counts as authenticated.
 *
 * `alg` is pinned to RS256, the algorithm Cloudflare Access issues. Accepting
 * whatever the token's own header names is the classic JWT break — `none`
 * skips verification entirely, and an HMAC algorithm would let a caller sign a
 * token with the public key as the shared secret — so the header's `alg` is
 * checked against the pin rather than used to select behavior.
 * @module @deepseek-ai/dsh-host-web-auth-cloudflare-access/jwt
 */

import { createPublicKey, verify as verifySignature, type JsonWebKey } from 'node:crypto'

/** The only signature algorithm Cloudflare Access issues, and the only one accepted. */
const REQUIRED_ALG = 'RS256'

/**
 * Tolerance applied to `exp` and `nbf`. Clock skew between the harness host and
 * Cloudflare's signer is real and unavoidable; one minute is small enough that
 * an expired token stays unusable in practice.
 */
const CLOCK_SKEW_SECONDS = 60

/** Decoded token header fields this package reads. */
interface TokenHeader {
  readonly alg?: unknown
  readonly kid?: unknown
}

/** Decoded token claims this package reads. */
interface TokenClaims {
  readonly aud?: unknown
  readonly iss?: unknown
  readonly sub?: unknown
  readonly email?: unknown
  readonly exp?: unknown
  readonly nbf?: unknown
}

/** A verified token's principal-bearing claims. */
export interface VerifiedToken {
  /** `email` when Cloudflare included one, else `sub`. */
  readonly subject: string
}

/** Why a token did not verify. Reported to logs only; callers see an unauthenticated request. */
export class TokenError extends Error {}

function decodeSegment(segment: string, what: string): unknown {
  // Buffer.from ignores characters outside the alphabet rather than throwing,
  // and utf8 decoding substitutes replacement characters, so only the JSON
  // parse below can reject a segment.
  const text = Buffer.from(segment, 'base64url').toString('utf8')
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new TokenError(`${what} is not JSON: ${String(error)}`)
  }
}

/** Split a compact JWT into its three segments. */
function splitToken(token: string): [string, string, string] {
  const segments = token.split('.')
  if (segments.length !== 3) throw new TokenError('token is not a three-segment compact JWT')
  return segments as [string, string, string]
}

/**
 * Read the key id a token asks to be verified with, after pinning `alg`.
 * @param token - the compact JWT.
 * @returns the `kid`, or undefined when the header names none.
 */
export function tokenKeyId(token: string): string | undefined {
  const header = decodeSegment(splitToken(token)[0], 'token header') as TokenHeader
  if (header.alg !== REQUIRED_ALG) {
    throw new TokenError(`token algorithm ${JSON.stringify(header.alg)} is not ${REQUIRED_ALG}`)
  }
  return typeof header.kid === 'string' ? header.kid : undefined
}

/**
 * Verify a token's signature and claims.
 * @param token - the compact JWT.
 * @param key - the JWK whose `kid` matched the token header.
 * @param audience - the Access application's AUD tag; the token's `aud` must contain it.
 * @param issuer - expected `iss`, the team domain origin.
 * @param nowSeconds - current time in epoch seconds.
 * @returns the verified principal.
 * @throws {@link TokenError} when any check fails.
 */
export function verifyToken(
  token: string,
  key: JsonWebKey,
  audience: string,
  issuer: string,
  nowSeconds: number,
): VerifiedToken {
  const [encodedHeader, encodedClaims, encodedSignature] = splitToken(token)
  // Re-read the header here too: a caller could otherwise verify one token's
  // key id and pass a different token to this function.
  const header = decodeSegment(encodedHeader, 'token header') as TokenHeader
  if (header.alg !== REQUIRED_ALG) {
    throw new TokenError(`token algorithm ${JSON.stringify(header.alg)} is not ${REQUIRED_ALG}`)
  }

  let publicKey: ReturnType<typeof createPublicKey>
  try {
    publicKey = createPublicKey({ key, format: 'jwk' })
  } catch (error) {
    throw new TokenError(`signing key is not a usable JWK: ${String(error)}`)
  }
  const signed = Buffer.from(`${encodedHeader}.${encodedClaims}`, 'ascii')
  const signature = Buffer.from(encodedSignature, 'base64url')
  if (!verifySignature('RSA-SHA256', signed, publicKey, signature)) {
    throw new TokenError('token signature does not verify')
  }

  const claims = decodeSegment(encodedClaims, 'token claims') as TokenClaims
  if (claims.iss !== issuer) {
    throw new TokenError(`token issuer ${JSON.stringify(claims.iss)} is not ${JSON.stringify(issuer)}`)
  }
  // `aud` is a string or an array of strings; a token is valid for this
  // deployment only if the configured application tag is among them.
  const audiences = typeof claims.aud === 'string'
    ? [claims.aud]
    : Array.isArray(claims.aud) ? claims.aud : []
  if (!audiences.includes(audience)) {
    throw new TokenError('token audience does not contain the configured application tag')
  }
  if (typeof claims.exp !== 'number') throw new TokenError('token has no numeric exp')
  if (claims.exp + CLOCK_SKEW_SECONDS <= nowSeconds) throw new TokenError('token has expired')
  if (typeof claims.nbf === 'number' && claims.nbf - CLOCK_SKEW_SECONDS > nowSeconds) {
    throw new TokenError('token is not yet valid')
  }

  const subject = typeof claims.email === 'string' && claims.email !== ''
    ? claims.email
    : typeof claims.sub === 'string' && claims.sub !== '' ? claims.sub : undefined
  if (subject === undefined) throw new TokenError('token carries neither email nor sub')
  return { subject }
}

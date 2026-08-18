# Web Authentication

English | [中文](web-auth.zh.md)

[dsh-host-web-auth](../../packages/host/web-auth) is the capability seam that decides who may reach the browser-facing surface of the GUI host. It provides `ctx.webAuth`: a provider registry, the sign-in session lifecycle, and the shared session-cookie encoding. It is not part of the agent loop, and it registers no route — the seam answers a question about a request; the carrier that owns the browser-authority fence applies the answer.

Source: [`packages/host/web-auth/src/index.ts`](../../packages/host/web-auth/src/index.ts)

## Why the seam exists, and what it is not

`dsh web` binds loopback by default, and every `/api` request passes a browser-trust fence that requires a `Host` which is loopback or a declared `trustedHosts` authority. That fence is a DNS-rebinding and cross-site defense and [deliberately not authentication](../../.agents/notes/implemented/architecture/2026-07-28-api-browser-trust-boundary.md): on an all-interfaces bind the CLI derives the machine's LAN literals into `trustedHosts` so its advertised LAN URL works, which means any client on that network reaches `session.prompt` — an agent that runs bash. The seam supplies the missing layer inside the product, so a deployment neither patches the shipped artifact nor fronts the harness with an external gateway.

Reachability remains the webserver binding's policy, and the authorities the fence answers to remain the connection row's. Authentication is layered on both: it adds a requirement, and it never relaxes the `Host` check.

## Identity and the two verification surfaces

```ts type-equiv
/** A principal one provider has verified for the current request. */
interface WebAuthIdentity {
  /** Registry id of the provider that verified this principal. */
  readonly provider: string
  /**
   * Label naming who was verified, for the sign-in session record and
   * diagnostics. Providers that authenticate a deployment secret rather than a
   * person use a fixed label; the seam never parses it.
   */
  readonly subject: string
}
```

```ts type-equiv
/**
 * The request facts a provider may read. Both HTTP representations the host
 * serves are accepted, matching the trust fence's own request type: the
 * `node:http` route handlers and the Fetch handlers the `/api` bridge builds.
 */
interface WebAuthRequest {
  readonly headers: IncomingHttpHeaders | Headers
}
```

```ts type-equiv
/** Where a sign-in attempt came from, for provider-owned rate limiting. */
interface WebAuthClient {
  /**
   * Remote peer address of the submitting socket, or undefined when the
   * carrier could not report one. Behind a reverse proxy every attempt shares
   * the proxy's address, so a provider keying a lockout on this value limits
   * the proxy as one client.
   */
  readonly address?: string
}
```

A provider supplies at least one verification surface, and the seam refuses one that supplies neither: such a provider could never authenticate anything while still making authentication required, locking the deployment out of its own harness.

```ts type-equiv
/**
 * One authentication mechanism. A provider supplies at least one verification
 * surface; the seam asserts that at registration, because a provider with
 * neither could never authenticate anything and would silently weaken a
 * deployment that believed it had mounted authentication.
 */
interface WebAuthProvider {
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
```

```ts type-equiv
/** Outcome of verifying a secret submitted through the seam's sign-in endpoint. */
type WebAuthSignInOutcome =
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
```

Verification order does not depend on registration order: an existing sign-in session is honored first with one map lookup, then each request-credential provider runs until one verifies. Only request-credential providers participate there, so adding an interactive provider never adds per-request cost.

## Sign-in results

```ts type-equiv
/** What a caller may learn about the authentication state without being signed in. */
interface WebAuthStatus {
  /** Whether non-loopback access requires authentication in this composition. */
  readonly required: boolean
  /** Whether THIS request already carries a verified principal. */
  readonly authenticated: boolean
  /** Whether a mounted provider accepts a submitted secret, i.e. whether the sign-in page can work. */
  readonly interactive: boolean
}
```

```ts type-equiv
/** Result of a sign-in attempt. */
type SignInResult =
  | {
    readonly outcome: 'verified'
    readonly identity: WebAuthIdentity
    /** `Set-Cookie` value establishing the browser session. */
    readonly setCookie: string
  }
  | SignInFailure
```

## Sessions and the cookie

Sessions live in process memory as SHA-256 digests of 256-bit random tokens, so a memory disclosure yields no usable cookie and sign-out revokes for real rather than waiting out a self-describing token. They are deliberately not persisted: restarting the harness invalidates every browser session, which is the trade for holding no signing key on disk. A live-record ceiling bounds the table, shedding expired records first and otherwise the oldest, so the newest session survives.

Every issued cookie carries `HttpOnly`, `SameSite=Strict`, `Path=/`, and a `Max-Age` matching the server-side record. `SameSite=Strict` is what makes an authenticated request safe to admit: a cross-site context — including a DNS-rebound page, which is a different site than the authority the cookie was issued for — never has the cookie attached, so possession of it evidences a first-party context rather than merely a reachable socket. Whether `Secure` is set is a deployment fact rather than something the process can observe, because a harness serves plain HTTP even when the browser reached it over HTTPS through a tunnel; `cookieSecure` selects `auto` (mark it when the request reports an HTTPS forwarding hop), `always`, or `never`.

## How the carrier applies the answer

[dsh-client-connection](../../packages/client/connection) is the Consumer. It reads the optional seam per request, mounts the sign-in surface behind its own authority fence, and combines the two decisions in [`api-request-gate.ts`](../../packages/client/connection/src/api-request-gate.ts):

- An ordinary `/api` request must pass the authority fence and, once a provider is mounted, must be loopback or carry a verified principal.
- A `loopback`-authority request — the configuration plane, native dialogs, the methods pinned because `trustedHosts` is not authentication — passes from loopback, or from a declared authority with a verified principal. That pin was waiting for exactly this condition.
- Loopback keeps reaching everything without a credential. Loopback access already implies running code as this process, so requiring a password of it would protect nothing while breaking health checks and local tooling.
- A credential never substitutes for the `Host` check, under either authority.

A composition that mounts no provider is unaffected in every one of these cases: the requirement follows the providers, not the seam row.

The sign-in surface is four routes under `/auth` — the login page, sign-in, sign-out, and status. They sit behind the authority fence so a rebound page cannot use sign-in as a password oracle, and the mutating ones require an `application/json` body, which forces any cross-site attempt into a preflight this server never answers. Static assets are not gated: the requirement covers `/api` and matches the fence's own scope.

## Providers

| Package | Verifies |
|---|---|
| [dsh-host-web-auth-password](../../packages/host/web-auth-password) | A submitted password, generated on first start and stored as a scrypt verifier, with per-client failure lockout |
| [dsh-host-web-auth-cloudflare-access](../../packages/host/web-auth-cloudflare-access) | The RS256 application token Cloudflare Access forwards, against the team's rotating key set |

Because the transport is orthogonal to the proof, a deployment changes one without the other: Cloudflare Tunnel, Tailscale, or a LAN reverse proxy in front, and whichever provider rows suit it behind.

<!-- BEGIN GENERATED cordis-surface (gen-cordis-catalog.ts) — do not edit between markers -->

<a id="cordis-surface"></a>

## Cordis API

Generated from source by `scripts/gen-cordis-catalog.ts` (verified fresh by `pnpm run verify-cordis-catalog` in doc-sync; regenerate with `pnpm run gen-cordis-catalog`) — this section is byte-identical in both language sides of the page. Signature blocks use a `ts cordis-catalog` fence and keep the original source JSDoc; dispatch modes are defined in the [primer](../cordis-primer.md#dispatch-modes), and the framework-inherited `ctx` API lives in [cordis-api/inherited.md](../cordis-api/inherited.md).

<a id="ctxwebauth--webauth"></a>

### `ctx.webAuth` — `WebAuth`

The authentication service. Providers register into it; the browser-transport Consumer reads it to decide whether a request may pass the `/api` fence.

Verification order is deliberate and not registration-dependent: an existing sign-in session is honored first (one map lookup, no provider work), then each provider's per-request credential check runs until one verifies. Only request-credential providers participate there, so adding an interactive provider never adds per-request cost.

```ts cordis-catalog
/**
 * Register one authentication provider. Disposed with the calling fiber.
 * @param provider - the mechanism; its `id` is the registry key.
 * @returns the disposer that unregisters it.
 * @throws when the id is already registered, or when the provider supplies
 * neither verification surface — such a provider could never authenticate
 * anything while still making authentication REQUIRED, locking the
 * deployment out of its own harness.
 */
register(provider: WebAuthProvider): () => void

/**
 * Resolve the verified principal behind one request.
 * @param request - the request's headers.
 * @returns the principal, or undefined when the request carries none.
 */
async authenticate(request: WebAuthRequest): Promise<WebAuthIdentity | undefined>

/**
 * Report the authentication state for one request.
 * @param request - the request's headers.
 * @returns what the caller may know before signing in.
 */
async status(request: WebAuthRequest): Promise<WebAuthStatus>

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
async signIn(secret: string, client: WebAuthClient, request: WebAuthRequest): Promise<SignInResult>

/**
 * Revoke the sign-in session a request presents.
 * @param request - the request's headers.
 * @returns the `Set-Cookie` value clearing the browser's cookie. Emitted even
 * when no live session matched, so a stale cookie is always cleared.
 */
signOut(request: WebAuthRequest): { setCookie: string }
```

Source: [`packages/host/web-auth/src/index.ts:119`](../../packages/host/web-auth/src/index.ts)
<!-- END GENERATED cordis-surface -->

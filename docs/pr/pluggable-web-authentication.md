# Pluggable web-access authentication (`ctx.webAuth`)

## Motivation

`dsh web` binds loopback by default, and every `/api` request passes a browser-trust fence that requires a `Host` which is loopback or a declared `trustedHosts` authority. That fence is a DNS-rebinding and cross-site defense, and the decision that introduced it says so explicitly: authentication was deliberately left out of scope. So a deployment that must be reachable from another machine — a container behind a tunnel, a LAN address, a VPN peer — has nothing inside the product that asks a remote caller to prove anything. `dsh web --host 0.0.0.0` makes the CLI derive the machine's LAN IP literals into `trustedHosts` so its advertised URL works, which means every client on that network reaches `session.prompt`: an agent that runs bash. The same gap cuts the other way — the `PRIVILEGED_METHODS` set is pinned to loopback precisely because `trustedHosts` is not authentication, so a legitimately remote operator cannot reach the configuration plane at all.

Deployments close the hole outside the product in two ways, and neither is acceptable as the answer:

- **Patch the installed artifact's trust check** so the fence accepts any `Host`. This disables a security check by editing a shipped file, deletes the rebinding defense for everyone who applies it, reverts on every upgrade, and authenticates nobody — it only removes the check that made the missing authentication visible.
- **Keep the harness on loopback and front it with a gateway that owns the login.** This leaves the harness unable to express its own requirement, so a composition is one misconfigured proxy away from an unauthenticated agent; it re-implements sign-in per deployment; and the loopback-pinned methods stay unreachable, because the gateway's traffic is not loopback.

Transport and proof vary independently. The same operator may front the harness with Cloudflare Tunnel today, Tailscale tomorrow, or a plain LAN reverse proxy, and may prove identity with a password, a tunnel's signed assertion, or something else. A design that fixes either choice inside the other is wrong for a harness where every other capability is a mountable row.

## Design

Authentication is a **capability seam**, and the requirement is applied by the plugin that already owns the browser-authority fence.

### The Service Definition

`@deepseek-ai/dsh-host-web-auth` provides `ctx.webAuth`: the provider registry, the sign-in session lifecycle, and the session-cookie encoding. It registers no route and names no transport. A provider supplies at least one of two verification surfaces — `verifyRequest` for a credential the request already carries, `verifySecret` for a secret submitted to the sign-in endpoint — and the registry refuses one that supplies neither, because such a row would make authentication required while never being able to admit anyone.

Verification honors a live sign-in session first with one map lookup, then runs each request-credential provider until one verifies. Registration order therefore carries no meaning, and an interactive-only provider adds no per-request cost.

**The requirement follows the providers, not the seam row**: `required` is `providers.size > 0`. Mounting the seam alone changes nothing, and unmounting a provider fiber removes the requirement with it.

### The Consumer

`@deepseek-ai/dsh-client-connection` is the Consumer — the one place that already owns the authority fence. `src/api-request-gate.ts` merges the two decisions for both authorities, reading the optional seam per request through `ctx.get('webAuth')` so no mounting order matters:

- An ordinary `/api` request passes the authority fence and, with a provider mounted, must also come from loopback or carry a verified principal.
- A `loopback`-authority request — the configuration plane, native dialogs, the `PRIVILEGED_METHODS` set — passes from loopback, or from a declared authority carrying a verified principal. Authentication is the condition that pin was waiting for, so a remote operator who signs in reaches the same surface as the local one.
- Loopback keeps reaching everything without a credential. Loopback access already means running code as the harness process, so a password there protects nothing while breaking health checks and local tooling.
- **A credential never substitutes for the `Host` check**, under either authority. An undeclared authority is refused even with a perfect credential.

The sign-in interface is four routes under `/auth` — page, sign-in, sign-out, status — mounted through `ctx.inject(['webAuth'], …)` and placed behind that same authority fence, so a rebound page cannot use the sign-in endpoint as a password oracle. The side-effecting routes require an `application/json` body, which forces any cross-site attempt into the CORS preflight this server never answers, and the sign-in body is size-capped.

### Sessions and the cookie

Sessions are SHA-256 digests of 256-bit random tokens held in process memory, so a memory disclosure yields no usable cookie and sign-out revokes for real. They are deliberately not persisted, which is the trade for holding no signing key on disk: restarting the harness invalidates every browser session.

Every issued cookie carries `HttpOnly`, `SameSite=Strict`, `Path=/`, and a `Max-Age` matching the server-side record. `SameSite=Strict` is what makes an authenticated request safe to admit: a cross-site context — including a DNS-rebound page, which is a different site than the authority the cookie was issued for — never has the cookie attached, so possession evidences a first-party context rather than a reachable socket. Whether `Secure` is set is a deployment fact rather than something the process observes, because the harness serves plain HTTP even when the browser arrived over HTTPS through a tunnel; `cookieSecure` selects `auto` (mark it when the request reports an HTTPS forwarding hop), `always`, or `never`.

### The two providers

`@deepseek-ai/dsh-host-web-auth-password` generates 25 symbols from a 32-symbol alphabet on first start — 125 bits — prints them once, and persists only their scrypt verifier. The credential file is created with exclusive create (`wx`) and owner-only permissions, so two processes starting on a fresh home directory converge on one credential instead of overwriting each other, and the loser reads the winner's file rather than invalidating a password it already printed. Consecutive failures lock a client out for a configured window; an expired lockout restarts the count, so the threshold always describes *consecutive* failures. Comparison is constant-time.

`@deepseek-ai/dsh-host-web-auth-cloudflare-access` verifies the RS256 application token Cloudflare Access forwards on every proxied request, from either the `Cf-Access-Jwt-Assertion` header or the `CF_Authorization` cookie. `alg` is pinned rather than read from the token, `iss` must equal the team-domain origin, and `aud` must contain the configured application tag, so a token minted for a sibling application in the same team does not reach this harness. The team's key set is cached with a TTL, an unknown `kid` triggers at most one refetch per cooldown window, and every failure — malformed token, fetch error, empty key set — is reported through the logger and treated as an unauthenticated request, never as a 500 a caller could use as an oracle.

### Enabling it

Nothing ships in a *profile*: the `dsh-web-app` bundle declares the three packages so the Loader can resolve them by name, exactly as it declares every other plugin its patch layer can mount, but no profile row references them. A deployment adds the rows through the official patch layer, `dsh --profile web --patch <file>`, alongside the reachability and trusted-authority config that remain their own owners':

```yaml
- id: webserver
  config:
    host: 0.0.0.0
    port: 3080

- id: connection
  config:
    trustedHosts: ['dsh.example.com']

- insert:
    - id: web-auth
      name: '@deepseek-ai/dsh-host-web-auth'
      config:
        cookieSecure: always

    - id: web-auth-password
      name: '@deepseek-ai/dsh-host-web-auth-password'
      config:
        file: !!js dshHomePath('web-auth', 'password.json')
```

Swapping the mechanism means swapping that last row. Mounting both provider rows is valid: a tunnel token authenticates automatically while the password stays available on the LAN.

## Impact on existing deployments

**None, by construction.** The requirement is `providers.size > 0`, so a composition without a provider row behaves exactly as it did before the seam existed: the `/auth` routes are never registered, the default `web` profile mounts nothing new, pure-loopback use is untouched, and loopback still reaches every method without a credential. A test asserts the no-provider composition is equivalent to one with no seam at all, and a booted default `web` profile answers `/auth/login`, `/auth/status`, and `/api/settings.describe` identically on this branch and on a base-commit checkout (in the shipped profile those first two paths reach the frontend's single-page fallback, as any unrouted path does — the 404 in the unit test is that composition's answer without the static frontend mounted).

Two deliberate changes for deployments that *do* opt in:

- A remote operator who authenticates now reaches the configuration plane and the native-dialog routes. This widens what a non-loopback client can do, and it is the reason the fence's `Host` requirement is kept rather than relaxed.
- Restarting the harness signs every browser out. A lost password is recovered by deleting the credential file, which rotates it on the next start.

One operational note: the Cloudflare Access provider trusts the team's key set over the network, so a key-set outage degrades header-credential callers to unauthenticated. Mounting a password provider alongside keeps sign-in available through that window.

## Scope of the change

Three new packages (`packages/host/web-auth`, `web-auth-password`, `web-auth-cloudflare-access`), two new modules in the Consumer (`api-request-gate.ts`, `auth-routes.ts`), the `dsh-web-app` bundle manifest and `pnpm-lock.yaml` entries that make the three packages resolvable by name, root tsconfig and catalog-generator registration, a bilingual subsystem page, and a bilingual Agent Note. The pre-existing trust-boundary Agent Note is updated in place to cross-link this decision, which layers on it rather than altering it.

## Testing

- `packages/client/connection/tests/api-request-gate.host.spec.ts` pins the merged decision: the no-provider equivalence, a perfect credential still failing an undeclared `Host` under both authorities, and the loopback-pinned plane opening to a verified principal.
- `packages/client/connection/tests/auth-routes.host.spec.ts` drives a bound HTTP server with the real seam and the real password provider through sign-in, lockout, sign-out, the media-type requirement, and the body-size cap, and asserts the no-provider composition answers `/auth/login` with 404.
- Provider suites use local fixtures only and touch no network: a generated RSA key pair plus a local JWKS server for Cloudflare Access, and a temporary home directory — including a four-way concurrent first start — for the password provider.

Verified locally: `pnpm run doc-sync` (28/28 gates), `pnpm run typecheck`, `pnpm run build`, `pnpm run lint`, and `pnpm run duplication` all pass. Coverage restricted to the new sources reports 100% statements, branches, functions, and lines (390/390 statements) across 201 passing tests.

### Verified against a booted harness

The composition above was booted — `dsh web --patch <file> --port <port> --host 127.0.0.1`, isolated `DSH_HOME` — and exercised over HTTP. The Loader resolved all three rows by name, the password banner printed once, and the credential file was written `0600` holding only the scrypt verifier:

| Request | Result |
| --- | --- |
| `GET /auth/login`, declared authority | 200 login page |
| `GET /auth/login`, undeclared authority | 403 |
| `POST /auth/sign-in`, generated password | 200, `Set-Cookie: …; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200` |
| `POST /api/settings.describe`, declared authority, no cookie | 403 |
| `POST /api/settings.describe`, declared authority, signed-in cookie | 200 |
| `POST /api/settings.describe`, loopback, no cookie | 200 |
| `POST /api/settings.describe`, undeclared authority, signed-in cookie | 403 |
| `POST /auth/sign-out`, then the same cookie | cookie cleared; `authenticated` back to `false` |
| three wrong passwords, then the correct one | 401 → 429 with `Retry-After`; the correct password stays 429 until the window expires |
| `POST /auth/sign-in` with `text/plain` | 415 |

A default `web` profile with no patch, booted on this branch and on a base-commit checkout, answers `/auth/login`, `/auth/status`, and `/api/settings.describe` identically.

Three test files fail under a full `pnpm run test`, and the same three fail on a base-commit checkout — `scripts/gen-third-party-notices.spec.ts` (the generator cannot read an optional platform package whose tarball is absent in this environment), `packages/subagent/subagent-codex/tests/real-product.spec.ts` (3 tests), and `packages/subagent/subagent-claude-code/tests/real-product.spec.ts`; all three need real third-party products present. Two script suites (`scripts/change-scope.spec.ts`, `scripts/install-lefthook.spec.ts`) fail under full-suite parallel load but pass when run in isolation on this branch. One `pnpm run hygiene` sub-gate (`rescope-vendor:check`) fails, identically on the base checkout; the other ten pass.

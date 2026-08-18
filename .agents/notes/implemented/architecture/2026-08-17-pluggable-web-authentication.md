# Agent Note: Web authentication is a capability seam the carrier layers on its authority fence

Status: implemented

English | [中文](2026-08-17-pluggable-web-authentication.zh.md)

## Problem

The GUI host serves `/api` over plain HTTP behind [one carrier-level browser-trust boundary](2026-07-28-api-browser-trust-boundary.md), which is a confused-deputy defense and deliberately not authentication. A deployment that must be reachable from another machine — a container behind a tunnel, a LAN address, a VPN peer — therefore has nothing inside the product that asks a remote caller to prove anything. `dsh web --host 0.0.0.0` makes the CLI derive the machine's LAN IP literals into `trustedHosts` so its advertised URL works, which means every client on that network reaches `session.prompt`: an agent that runs bash. The `PRIVILEGED_METHODS` set is pinned to loopback precisely because `trustedHosts` is not authentication, so a legitimately remote operator also cannot reach the configuration plane at all.

Deployments close the hole outside the product in two ways. One edits the installed artifact's trust check so the fence accepts any `Host`, which disables a security check by patching a shipped file and reverts on every upgrade. The other keeps the harness on loopback and fronts it with a gateway that owns the login, which leaves the harness unable to express its own requirement, re-implements sign-in per deployment, and still leaves the loopback-pinned methods unreachable because the gateway's traffic is not loopback.

Transport and proof vary independently: the same operator may front the harness with Cloudflare Tunnel, Tailscale, or a LAN reverse proxy, and may prove identity with a password, a tunnel's signed assertion, or something else. A design that fixes either choice inside the other is wrong for this product, where every other capability is a mountable row.

## Decision

Authentication is a capability seam with two provider packages, and the requirement is applied by the plugin that already owns the browser-authority fence.

`@deepseek-ai/dsh-host-web-auth` provides `ctx.webAuth`: the provider registry, the sign-in session lifecycle, and the session-cookie encoding. It registers no route and names no transport. A provider supplies at least one of two verification surfaces — `verifyRequest` for a credential the request already carries, `verifySecret` for a secret submitted to the sign-in endpoint — and the registry refuses one that supplies neither, because such a row makes authentication required while never being able to admit anyone. Verification honors a live sign-in session first with one map lookup, then runs each request-credential provider until one verifies, so registration order carries no meaning and an interactive-only provider adds no per-request cost.

The requirement follows the providers, not the seam row: `required` is `providers.size > 0`. Mounting the seam alone changes nothing, and unmounting a provider fiber removes the requirement with it.

`@deepseek-ai/dsh-client-connection` is the Consumer. [`src/api-request-gate.ts`](../../../../packages/client/connection/src/api-request-gate.ts) merges the two decisions for both authorities, and the seam is read per request through `ctx.get('webAuth')` so no mounting order matters:

- An ordinary `/api` request passes the authority fence, and with a provider mounted must also come from loopback or carry a verified principal.
- A `loopback`-authority request — the configuration plane, native dialogs, and the `PRIVILEGED_METHODS` set — passes from loopback, or from a declared authority carrying a verified principal. Authentication is the condition that pin was waiting for, so a remote operator who signs in reaches the same surface as the local one.
- Loopback keeps reaching everything without a credential. Loopback access already means running code as the harness process, so a password there protects nothing while breaking health checks and local tooling.
- A credential never substitutes for the `Host` check, under either authority.

The sign-in interface is four routes under `/auth` — page, sign-in, sign-out, status — mounted through `ctx.inject(['webAuth'], …)` and placed behind the same authority fence, so a rebound page cannot use the sign-in endpoint as a password oracle. The side-effecting routes require an `application/json` body, which forces any cross-site attempt into the preflight this server never answers. Static assets stay ungated: the requirement covers `/api`, matching the fence's own scope.

Sessions are SHA-256 digests of 256-bit random tokens held in process memory, so a memory disclosure yields no usable cookie and sign-out revokes for real. They are deliberately not persisted, which is the trade for holding no signing key on disk: restarting the harness invalidates every browser session. Every issued cookie carries `HttpOnly`, `SameSite=Strict`, `Path=/`, and a `Max-Age` matching the server-side record. `SameSite=Strict` is what makes an authenticated request safe to admit: a cross-site context, including a DNS-rebound page, never has the cookie attached, so possession evidences a first-party context rather than a reachable socket. Whether `Secure` is set is a deployment fact rather than something the process observes, because the harness serves plain HTTP even when the browser arrived over HTTPS through a tunnel; `cookieSecure` selects `auto`, `always`, or `never`.

Two providers ship, covering the interactive and the delegated case:

- `@deepseek-ai/dsh-host-web-auth-password` generates 25 symbols from a 32-symbol alphabet on first start — 125 bits — prints them once, and persists only their scrypt verifier. The credential file is created with exclusive create and owner-only permissions, so two processes starting on a fresh home directory converge on one credential instead of overwriting each other, and the loser reads the winner's file rather than invalidating a password it already printed. Consecutive failures lock a client out for a configured window, and an expired lockout restarts the count so the threshold always describes consecutive failures.
- `@deepseek-ai/dsh-host-web-auth-cloudflare-access` verifies the RS256 application token Cloudflare Access forwards on every proxied request. `alg` is pinned rather than read from the token, `iss` must equal the team-domain origin, and `aud` must contain the configured application tag so a token minted for a sibling application in the same team does not reach this harness. The team's key set is cached with a TTL, an unknown `kid` triggers at most one refetch per cooldown, and every failure — malformed token, fetch error, empty key set — is reported through the logger and treated as an unauthenticated request, never as a 500 a caller could use as an oracle.

## Alternatives considered

- **Patch the authority fence to accept any `Host`.** Rejected: it deletes the DNS-rebinding defense for every deployment that applies it, it is applied by editing an installed artifact rather than by configuration, and it does not authenticate anyone — it only removes the check that made the missing authentication visible.
- **Front the harness with an external gateway and add nothing to the product.** Rejected: the harness cannot express its own requirement, so a composition is one misconfigured proxy away from an unauthenticated agent; the loopback-pinned privileged methods remain unreachable for a remote operator because gateway traffic is not loopback; and each deployment re-implements sign-in. A gateway remains fully supported in front of this seam — it is the transport, not the proof.
- **Bearer tokens or an API key header instead of a cookie session.** Rejected as the primary mechanism: the browser is the client, and a header-only scheme forces the token into script-reachable storage, losing `HttpOnly` and the `SameSite=Strict` property that makes admission safe. A provider may still authenticate a header credential — that is what `verifyRequest` is, and what the Cloudflare Access provider uses.
- **Enforce authentication in `dsh-host-apiproxy` beside the media-type fence, or in the webserver.** Rejected: the authority fence is the decision this one composes with, and it lives in `dsh-client-connection`. Splitting the two across packages would let one pass while the other refuses, and the webserver owns reachability, a separate policy.
- **Persist sessions so restarts survive.** Rejected: it requires a signing key or a session store on disk, and the cost of the current choice is one sign-in after a restart.
- **One authentication plugin with a mode switch instead of a seam.** Rejected: a mode enum grows a branch per mechanism inside one package, cannot express two mechanisms at once — a tunnel assertion for normal use plus a password for direct LAN access — and makes a third-party mechanism a fork instead of a row.
- **Treat `trustedHosts` as the authorization list.** Rejected: it names which authorities a browser may claim, which is a rebinding defense; every client that can reach a declared authority satisfies it, so it cannot distinguish operators.

## Testing

`packages/client/connection/tests/api-request-gate.host.spec.ts` pins the merged decision, including that a composition with no provider is equivalent to one with no seam at all, that a perfect credential still fails an undeclared `Host` under both authorities, and that the loopback-pinned plane opens to a verified principal. `packages/client/connection/tests/auth-routes.host.spec.ts` drives a bound HTTP server with the real seam and the real password provider through sign-in, lockout, sign-out, and the media-type and body-size limits, and asserts the no-provider composition answers `/auth/login` with 404. The provider suites use local fixtures only: a generated RSA key pair and a local JWKS server for Cloudflare Access, and a temporary home directory — including a four-way concurrent first start — for the password provider.

## Consequences

- A deployment enables authentication with a patch layer that adds the seam row and one provider row, so the transport in front of the harness and the proof inside it are chosen independently.
- Compositions without a provider row are unaffected in every path, including the absence of the `/auth` routes. The default `web` profile and pure-loopback use behave exactly as they did before the seam existed.
- Remote operators reach the configuration plane and native-dialog routes once they authenticate, which is a deliberate widening of what a non-loopback client can do, and the reason the fence's `Host` requirement is kept rather than relaxed.
- Restarting the harness signs every browser out, and a lost password is recovered by deleting the credential file, which rotates it on the next start.
- The Cloudflare Access provider trusts the team's key set over the network, so a key-set outage degrades to unauthenticated for header-credential callers; a mounted password provider keeps sign-in available through that window.

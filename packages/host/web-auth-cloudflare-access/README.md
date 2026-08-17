# `@deepseek-ai/dsh-host-web-auth-cloudflare-access`

English | [中文](README.zh.md)

Cloudflare Access provider for the [web-access authentication seam](../web-auth/README.md). It verifies the signed application token Cloudflare Access forwards on every proxied request and reports the authenticated user.

## Why verification is not optional

Cloudflare Access terminates the user's session at the edge and forwards a JWT in `Cf-Access-Jwt-Assertion` (or, for browser navigations, a `CF_Authorization` cookie). Verifying that token's signature and audience here is what makes the tunnel's decision trustworthy to the harness: without it, any caller that reaches the origin directly — bypassing the tunnel, which is exactly what an exposed container port permits — could simply assert the header.

`alg` is pinned to RS256 rather than read from the token. Trusting the token's own header is the classic JWT break: `none` skips verification entirely, and an HMAC algorithm would let a caller sign a token using the public key as the shared secret. A token is accepted only when its signature verifies against the team's current key set, its `iss` equals the team domain origin, its `aud` contains the configured application tag — which stops a token minted for another application in the same team from reaching this harness — and its validity window holds within one minute of clock skew. The identity subject is the token's `email`, falling back to `sub`.

A malformed, forged, or expired token is reported through the logger and answered as an ordinary unauthenticated request. A key-set fetch failure is treated the same way rather than failing the request, so an outage at the edge cannot be turned into a 500 oracle.

## Signing keys

Cloudflare rotates signing keys, so they are fetched rather than configured. A successful key set is served for an hour before a scheduled refresh, and a token naming an unknown key id triggers at most one refetch per cooldown window — otherwise a stream of forged key ids would become unbounded outbound requests. Concurrent callers share one in-flight fetch, and a refresh replaces the set wholesale so a key Cloudflare withdrew stops verifying tokens.

## Config

| Key | Default | Meaning |
|---|---|---|
| `teamDomain` | required | The Access team domain, for example `example.cloudflareaccess.com`. Must be a bare hostname; anything else fails the load rather than producing an issuer no token can match. The expected `iss` is this domain's `https://` origin. |
| `audience` | required | The Access application's Audience (AUD) tag. |
| `certsUrl` | `https://<teamDomain>/cdn-cgi/access/certs` | Signing key-set endpoint, for deployments on a custom Access hostname. |

## Deployment note

This provider authenticates; it does not make the harness reachable. The webserver row still decides the bind address, and the connection row still declares the authorities the fence answers to — a tunnelled deployment on `dsh.example.com` needs that name in `trustedHosts` whether or not a provider is mounted.

## Model Experience

None, as the Cloudflare Access provider verifies a forwarded token for the authentication seam and registers nothing model-facing.

#### KV Cache effect

None; this package neither assembles nor sends a provider request.

## Known Limitations and Deferred Work

- **No group or email authorization** — any token valid for the configured application is accepted, so access control stays entirely in the Access policy. Filtering by claim would duplicate a decision Cloudflare already owns, but a deployment sharing one application across audiences it wants to separate cannot express that here.
- **Only RS256** — the algorithm Cloudflare Access issues. A team configured for another signing algorithm is refused rather than negotiated.
- **The key set is not preloaded** — the first request after mount pays the key-set fetch, and its five-second timeout is a fixed bound rather than a configured one.

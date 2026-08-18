# `@deepseek-ai/dsh-host-web-auth`

English | [中文](README.zh.md)

Service Definition for the web-access authentication seam (`ctx.webAuth`): the provider registry, the browser sign-in session lifecycle, and the one place the session cookie's security attributes are decided. Mount it with at least one provider to require authentication for remote access to the Web GUI; a composition that mounts no provider leaves the harness exactly as it was.

The seam answers one question — does this request carry a verified principal? — and mints or revokes the browser session that records one. It registers no route and reads no `Host`: the Consumer that already owns the browser-authority fence, [`dsh-client-connection`](../../client/connection/README.md), mounts the sign-in surface behind that fence and enforces the requirement on `/api`. That keeps which authorities a deployment answers to a single fact in a single place, and keeps this package independent of the transport it protects.

## Why this exists

`dsh web` binds loopback by default, and the `/api` fence trusts a `Host` allowlist. That fence is a DNS-rebinding and cross-site defense, [by design not an auth layer](../../../.agents/notes/implemented/architecture/2026-07-28-api-browser-trust-boundary.md): on an all-interfaces deployment the CLI derives the machine's LAN literals into `trustedHosts`, so any LAN client reaches `session.prompt` — an agent that runs bash. Authenticating remote access needed a product capability rather than a patched artifact or an external gateway, and it needed to be swappable, because the transport a deployment uses (Cloudflare Tunnel, Tailscale, a reverse proxy on the LAN) is orthogonal to how it proves identity.

## Service API

| Member | Purpose |
|---|---|
| `register(provider)` | Register one mechanism; returns the disposer, scoped to the calling fiber. Refuses a duplicate id, and refuses a provider supplying neither verification surface. |
| `required` | Whether any provider is mounted, i.e. whether authentication is required at all. |
| `interactive` | Whether a mounted provider accepts a submitted secret, i.e. whether the sign-in page can work. |
| `authenticate(request)` | The verified principal behind one request, or `undefined`. |
| `status(request)` | `{ required, authenticated, interactive }` for the sign-in page. |
| `signIn(secret, client, request)` | Verify a submitted secret and mint a session; returns the `Set-Cookie` value or why no session was minted. |
| `signOut(request)` | Revoke the presented session; returns the `Set-Cookie` value clearing it. |

## Provider roles

A provider supplies one or both verification surfaces, and the seam refuses one that supplies neither — such a provider could never authenticate anything while still making authentication required, locking the deployment out of its own harness.

- **`verifyRequest(request)`** — a credential the request carries on its own, such as a tunnel's signed assertion header. Called on every gated request, so it must be cheap and must not block on the network per call. [`web-auth-cloudflare-access`](../web-auth-cloudflare-access/README.md) is one.
- **`verifySecret(secret, client)`** — a secret submitted to the sign-in endpoint; success earns a browser session cookie. [`web-auth-password`](../web-auth-password/README.md) is one. The verdict distinguishes `rejected` from `locked`, and a `locked` verdict ends the attempt rather than falling through to the next provider, so a second mounted provider can never be used to side-step the first one's rate limit.

Verification order does not depend on registration order: an existing sign-in session is honored first with one map lookup, then each request-credential provider runs until one verifies.

## Session records and the cookie

Sessions live in process memory as SHA-256 digests of high-entropy tokens, so a memory disclosure yields no usable cookie and sign-out revokes for real. They are deliberately not persisted: restarting the harness invalidates every browser session, which is the trade for holding no signing key on disk. A live-record ceiling bounds the table, evicting the oldest first.

Every issued cookie carries `HttpOnly`, `SameSite=Strict`, `Path=/`, and a `Max-Age` matching the server-side record. `SameSite=Strict` is what makes an authenticated request safe to admit through the authority fence: a cross-site context — including a DNS-rebound page, which is a different site than the authority the cookie was issued for — never has the cookie attached, so possession of it evidences a first-party context rather than merely a reachable socket.

`Secure` is a deployment fact, not something the process can observe: a harness serves plain HTTP even when the browser reached it over HTTPS through a tunnel. `cookieSecure: auto` marks the attribute when the request reports an HTTPS forwarding hop, `always` suits a deployment reachable only over HTTPS, and `never` is required for plain-HTTP LAN serving. `auto` trusts `x-forwarded-proto` only to ADD the attribute, so a client that strips the header weakens nothing but its own cookie.

## Config

| Key | Default | Meaning |
|---|---|---|
| `sessionTtlSeconds` | `43200` (12 h) | Browser session lifetime; the record expires server-side at the same moment. |
| `cookieSecure` | `auto` | Whether issued cookies are marked `Secure`. |

## Enabling it

The seam ships in no profile: mounting it is what turns authentication on, so the default `web` profile is unaffected. A deployment adds the rows through the official patch layer — `dsh --profile web --patch <file>` — and, because reachability and trusted authorities remain their owners' config, sets those in the same overlay:

```yaml
# Listen beyond loopback; publish this port only where the tunnel or proxy reaches it.
- id: webserver
  config:
    host: 0.0.0.0
    port: 3080

# The authority the browser addresses. Required with or without authentication:
# the fence is a DNS-rebinding defense and authentication never replaces it.
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

The first start prints the generated password once. Swapping the mechanism means swapping that last row — for a Cloudflare Access deployment, `@deepseek-ai/dsh-host-web-auth-cloudflare-access` with a `teamDomain` and `audience` instead — and mounting both rows is valid: a tunnel token authenticates automatically while the password remains available on the LAN.

## Model Experience

None, as the authentication seam decides who may reach the carrier and registers nothing model-facing.

#### KV Cache effect

None; this package neither assembles nor sends a provider request.

## Known Limitations and Deferred Work

- **Sign-in sessions do not survive a restart** — records are process-local, so every browser re-authenticates after the harness restarts. Persisting them would mean holding a signing key or a session table on disk, which is a larger decision than this seam settles.
- **Static assets stay public** — the requirement covers `/api` and the sign-in surface, matching the fence's own scope. An unauthenticated browser still downloads the shell bundle (the same public artifact npm serves) and only fails once it calls the API; it is not redirected to the sign-in page. Gating the SPA would mean owning the webserver's single fallback seat, which [`frontend-static`](../frontend-static/README.md) holds.
- **No in-app sign-out or session UI** — `signOut` is reachable over HTTP but no browser plugin surfaces it, so ending a session early means clearing the cookie or restarting the harness.

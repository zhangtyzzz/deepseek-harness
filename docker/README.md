# Container image for the dsh web surface

English | [中文](README.zh.md)

Runs `dsh web` in a container, reachable from outside the host, with the harness
itself asking remote callers to authenticate. Nothing here patches an installed
file and nothing sits in front of the harness: reachability comes from the
official patch layer and admission comes from the in-product `ctx.webAuth` seam.

## Why a source build

The pluggable web-authentication capability lives on `master` but is not in any
published `@deepseek-ai/dsh` release yet, so the image builds the workspace
instead of installing the npm artifact.

## Pulling instead of building

`.github/workflows/docker-image.yml` publishes a multi-platform image — `linux/amd64`
and `linux/arm64`, each built on its own native runner — to
`ghcr.io/<repository owner>/dsh-web` on every push to `master`. For this fork that is
`ghcr.io/zhangtyzzz/dsh-web`:

```bash
docker pull ghcr.io/zhangtyzzz/dsh-web:latest
```

A pull request builds both platforms without publishing, so a change that breaks
the image is caught before the tag moves.

## Build and run

```bash
# from the repository root
docker build -f docker/Dockerfile -t dsh-web:local .

# loopback only — nothing outside the host can reach it
docker run --rm -p 127.0.0.1:3080:3080 -v dsh-home:/dsh-home dsh-web:local

# reachable as https://dsh.example.com through a tunnel or reverse proxy
docker run -d --name dsh \
  -p 3080:3080 \
  -e DSH_TRUSTED_HOST=dsh.example.com \
  -e DSH_COOKIE_SECURE=always \
  -v dsh-home:/dsh-home \
  -v "$PWD/workspace:/workspace" \
  dsh-web:local
```

Or with compose, from this directory: `docker compose up -d --build`.

**The password prints once, on first start.** Read it from the container logs
(`docker logs dsh`) — only its scrypt verifier is persisted, under
`/dsh-home/web-auth/password.json`. Deleting that file rotates the password on
the next start.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `DSH_TRUSTED_HOST` | *(empty)* | Comma-separated authorities the `/api` trust fence accepts, e.g. `dsh.example.com,192.168.1.10:3080`. Empty means loopback-only, whatever the port mapping says. |
| `DSH_PORT` | `3080` | Port inside the container. |
| `DSH_BIND` | `0.0.0.0` | Bind address inside the container. Set through the patch layer, because `dsh web --host 0.0.0.0` is refused by the CLI on purpose. |
| `DSH_COOKIE_SECURE` | `auto` | `auto` marks the session cookie `Secure` when the request reports an HTTPS forwarding hop; `always` for HTTPS-only deployments; `never` for plain-HTTP LAN. |
| `DSH_SESSION_TTL_SECONDS` | `43200` | Sign-in session lifetime. |
| `DSH_AUTH_MAX_ATTEMPTS` | `5` | Consecutive failures from one client before a lockout. |
| `DSH_AUTH_LOCKOUT_SECONDS` | `300` | How long a triggered lockout refuses that client. |
| `DSH_PRINT_CONFIG` | `0` | `1` echoes the rendered patch overlay to stderr at start. |
| `DSH_HOME` | `/dsh-home` | Harness state: sessions, settings, credentials, password verifier. |

## What the entrypoint renders

`$DSH_HOME/docker.cordis.yml`, regenerated on every start and passed as
`--patch`: a `webserver` row that binds `${DSH_BIND}:${DSH_PORT}`, a `connection`
row carrying `trustedHosts`, and two inserted rows mounting
`@deepseek-ai/dsh-host-web-auth` and `@deepseek-ai/dsh-host-web-auth-password`.

## Things worth knowing before exposing this

- **`DSH_TRUSTED_HOST` is not optional for remote access.** A request whose
  `Host` is neither loopback nor a declared authority is refused even with a
  valid session cookie — that is the DNS-rebinding defense, and authentication
  layers on it rather than replacing it.
- **An authenticated remote operator reaches the configuration plane**, including
  `credentials.set` and the settings methods, which are pinned to loopback for
  anonymous callers. That is the intended consequence of signing in.
- **Restarting the container signs every browser out.** Sessions are process-local
  by design; no signing key is written to disk.
- **Volumes must be writable by uid 1000.** The agent runs arbitrary code, so the
  container does not run as root; the entrypoint fails loudly if `DSH_HOME` is
  not writable.
- The image carries the harness's own tool surface (`bash`, `git`, `ripgrep`).
  Anyone who signs in can run commands in the container as uid 1000.

## Not done here

- Only the password provider is mounted. The Cloudflare Access provider ships in
  the same seam; adding it means one more inserted row plus a `cloudflared`
  sidecar.
- The image ships the built workspace, so it is large. Slimming it means teaching
  `pnpm deploy` to produce a runnable tree — today it does not.
- If this goes upstream, the user-facing half of this page belongs under `docs/`
  with a `.zh.md` pair, which the documentation gates would then enforce.

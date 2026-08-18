# `@deepseek-ai/dsh-host-web-auth-password`

English | [中文](README.zh.md)

Local-password provider for the [web-access authentication seam](../web-auth/README.md). It generates a password on first start, stores only a scrypt verifier for it, and rate-limits consecutive failures per client.

## First start and rotation

There is no default, built-in, or documented password: on first start the provider generates 25 symbols from a 32-symbol alphabet — 125 bits — and prints it once, because only a scrypt verifier is persisted and the password is not recoverable afterwards. The alphabet omits `I`, `L`, `O`, and `U`, which removes transcription ambiguity when reading the password off a terminal and makes the digits `0` and `1` unambiguous in turn.

The credential file is created with owner-only permissions through an exclusive create, so two processes racing a fresh harness home converge on one credential rather than silently overwriting each other; the loser of that race reads the winner's file instead of invalidating the password it already printed. Deleting the file rotates the password on the next start. Its `version` is checked on read and a mismatch fails loud — this repository rejects old on-disk formats rather than migrating them.

## Lockout

The stored password carries 125 bits of entropy, so guessing is infeasible once attempts are throttled; the lockout is what makes a password endpoint safe to expose at all. After `maxAttempts` consecutive failures from one client the provider reports `locked` for `lockoutSeconds`, which the seam surfaces as HTTP 429 with `Retry-After` and which stops the attempt from falling through to another provider. A correct password verifies before a failure is recorded, so a client whose lockout has just expired succeeds on its first attempt. A tracked-client ceiling bounds the counter table, evicting entries closest to expiry first so an in-force lockout outlives stale counters.

Attempts key on the submitting socket's address. Behind a reverse proxy every attempt shares the proxy's address, so the lockout limits the proxy as one client.

## Config

| Key | Default | Meaning |
|---|---|---|
| `file` | required | Absolute path of the credential file. Where harness state lives is an assembly fact of the composing application, so the shipped bundle supplies a harness-home path and a deployment never hardcodes one. |
| `maxAttempts` | `5` | Consecutive failures from one client that trigger a lockout. |
| `lockoutSeconds` | `300` | How long a triggered lockout refuses that client. |

## Model Experience

None, as the password provider verifies a submitted secret for the authentication seam and registers nothing model-facing.

#### KV Cache effect

None; this package neither assembles nor sends a provider request.

## Known Limitations and Deferred Work

- **The password cannot be supplied by the operator** — there is no config or credential-reference path for an externally chosen secret, so a container that does not persist its harness home prints a new password on every start. Accepting one would mean deciding how a weak operator-supplied value is refused, which this package does not settle.
- **Lockout state is process-local** — counters reset when the harness restarts, so a restart loop clears an in-force lockout.
- **One shared password, no accounts** — the provider authenticates possession of the harness credential, not a person; its identity subject is a fixed label. Multi-user access is a different provider's job.

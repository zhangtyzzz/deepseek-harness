/**
 * `@deepseek-ai/dsh-host-web-auth-password` — registers a local-password
 * provider with `ctx.webAuth`.
 *
 * On first start it generates a 125-bit password, persists only a scrypt
 * verifier for it (owner-readable), and prints the password once: it is never
 * recoverable afterwards, and there is no default or built-in value to leak
 * across deployments. Deleting the credential file generates a new password on
 * the next start.
 * @module @deepseek-ai/dsh-host-web-auth-password
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { LOGIN_PATH } from '@deepseek-ai/dsh-host-web-auth'
import { loadOrCreateCredential } from './credential-file.ts'
import { PasswordAuthProvider } from './provider.ts'

export { generatePassword, loadOrCreateCredential, verifyPassword } from './credential-file.ts'
export type { LoadedCredential } from './credential-file.ts'
export { PASSWORD_PROVIDER_ID, PASSWORD_SUBJECT, PasswordAuthProvider } from './provider.ts'
export type { PasswordAuthProviderOptions } from './provider.ts'

/** Stable Cordis plugin name. */
export const name = 'web-auth-password'

/** The authentication seam this provider registers into. */
export const inject = ['webAuth']

/** Plugin config. */
export interface Config {
  /**
   * Absolute path of the credential file holding the scrypt verifier. Where
   * harness state lives is an assembly fact of the composing application, so
   * the shipped bundle supplies a harness-home path and a deployment never
   * hardcodes one.
   */
  file: string
  /** Consecutive failed attempts from one client that trigger a lockout. */
  maxAttempts?: number
  /** How long a triggered lockout refuses further attempts from that client. */
  lockoutSeconds?: number
}

export const Config: z<Config> = z.object({
  file: z.string().required(),
  maxAttempts: z.natural().min(1).default(5),
  lockoutSeconds: z.natural().min(1).default(300),
})

/** Schema defaults, restated for hand-built contexts that pass a partial config. */
const DEFAULT_MAX_ATTEMPTS = 5
const DEFAULT_LOCKOUT_SECONDS = 300

/**
 * Deliver a freshly generated password to the operator. Printed rather than
 * logged through the logger because it is a one-time setup instruction for the
 * person at the terminal, the same channel and reasoning as the Web URL line.
 * @param password - the generated password.
 * @param file - credential file path, so the operator knows what to delete to rotate.
 */
function announce(password: string, file: string): void {
  console.log([
    '',
    '  ┌─ DeepSeek Harness web sign-in ─────────────────────────────',
    '  │',
    `  │  Password: ${password}`,
    '  │',
    '  │  Shown once. Only a scrypt verifier is stored, at',
    `  │  ${file}`,
    '  │  Delete that file to generate a new password.',
    `  │  Sign in at ${LOGIN_PATH}`,
    '  └────────────────────────────────────────────────────────────',
    '',
  ].join('\n'))
}

/**
 * Load or generate the harness password credential and register the provider.
 * @param ctx - plugin context carrying the `webAuth` seam.
 * @param config - validated {@link Config}.
 */
export async function apply(ctx: Context, config: Config): Promise<void> {
  const { credential, generated } = await loadOrCreateCredential(config.file)
  ctx.webAuth.register(new PasswordAuthProvider({
    credential,
    maxAttempts: config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
    lockoutSeconds: config.lockoutSeconds ?? DEFAULT_LOCKOUT_SECONDS,
  }))
  if (generated !== undefined) announce(generated, config.file)
}

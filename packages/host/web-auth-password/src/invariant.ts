/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-host-web-auth-password`.
 * @module @deepseek-ai/dsh-host-web-auth-password/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-host-web-auth-password'

/** Cordis companion plugin name. */
export const name = 'host-web-auth-password-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: the provider owns no service, publishes no event stream, and keeps its
 * failure counters private; each verdict is computed per attempt from the credential file loaded
 * at mount.
 */
const install: InvariantInstaller = () => {}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
/* jscpd:ignore-end */

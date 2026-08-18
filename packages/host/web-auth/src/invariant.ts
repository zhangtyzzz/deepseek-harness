/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-host-web-auth`.
 * @module @deepseek-ai/dsh-host-web-auth/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-host-web-auth'

/** Cordis companion plugin name. */
export const name = 'host-web-auth-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: the provider map and the sign-in session table are private, the
 * seam publishes no event stream or mutable data another plugin observes, and every
 * verification decision is made per call from the request's own headers.
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

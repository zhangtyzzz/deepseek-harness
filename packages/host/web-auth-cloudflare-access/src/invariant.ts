/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-host-web-auth-cloudflare-access`.
 * @module @deepseek-ai/dsh-host-web-auth-cloudflare-access/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-host-web-auth-cloudflare-access'

/** Cordis companion plugin name. */
export const name = 'host-web-auth-cloudflare-access-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: the provider owns no service and publishes no event stream, and its key
 * cache is private state refreshed from the configured endpoint; each verdict is computed per
 * request from that request's own token.
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

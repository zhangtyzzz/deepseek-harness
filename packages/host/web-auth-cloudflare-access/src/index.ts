/**
 * `@deepseek-ai/dsh-host-web-auth-cloudflare-access` — registers a provider
 * that treats a valid Cloudflare Access application token as proof of identity.
 *
 * Cloudflare Access terminates the user's session at the edge and forwards a
 * signed JWT on every request. Verifying that signature and audience here is
 * what makes the tunnel's decision trustworthy to the harness: without it, any
 * caller that reaches the origin directly — bypassing the tunnel — could simply
 * assert the header.
 * @module @deepseek-ai/dsh-host-web-auth-cloudflare-access
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type {} from '@deepseek-ai/dsh-host-web-auth'
import { CloudflareAccessProvider } from './provider.ts'

export { CLOUDFLARE_ACCESS_PROVIDER_ID, CloudflareAccessProvider } from './provider.ts'
export type { CloudflareAccessProviderOptions } from './provider.ts'

/** Stable Cordis plugin name. */
export const name = 'web-auth-cloudflare-access'

/** The authentication seam this provider registers into. */
export const inject = ['webAuth']

/** Plugin config. */
export interface Config {
  /**
   * The Access team domain, for example `example.cloudflareaccess.com`. The
   * expected token issuer is this domain's `https://` origin, and the signing
   * key set is fetched from it unless {@link Config.certsUrl} overrides.
   */
  teamDomain: string
  /**
   * The Access application's Audience (AUD) tag. A token is accepted only when
   * its `aud` contains this value, which is what stops a token minted for
   * another application in the same team from reaching this harness.
   */
  audience: string
  /**
   * Signing key-set endpoint, when it is not the team domain's standard path.
   * Deployments on a custom Access hostname need this, and it is the seam a
   * test uses to serve a local key set instead of reaching Cloudflare.
   */
  certsUrl?: string
}

export const Config: z<Config> = z.object({
  teamDomain: z.string().required(),
  audience: z.string().required(),
  certsUrl: z.string(),
})

/**
 * Register the Cloudflare Access provider with `ctx.webAuth`.
 * @param ctx - plugin context carrying the `webAuth` seam.
 * @param config - validated {@link Config}.
 */
export function apply(ctx: Context, config: Config): void {
  // Fail at load rather than on the first request: a team domain carrying a
  // scheme or path would silently produce an issuer no token can match.
  if (!/^[a-z0-9.-]+$/i.test(config.teamDomain)) {
    throw new Error(
      `web-auth-cloudflare-access: teamDomain ${JSON.stringify(config.teamDomain)} must be a bare hostname`,
    )
  }
  ctx.webAuth.register(new CloudflareAccessProvider({
    issuer: `https://${config.teamDomain}`,
    audience: config.audience,
    certsUrl: config.certsUrl ?? `https://${config.teamDomain}/cdn-cgi/access/certs`,
    onRejected: (reason) => { ctx.logger.debug('cloudflare access token rejected: %s', reason) },
  }))
}

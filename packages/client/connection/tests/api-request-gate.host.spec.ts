/**
 * The admission decision once authentication is in play: the authority fence is
 * unchanged and additive, loopback keeps reaching everything, and a verified
 * principal opens the loopback-pinned configuration plane.
 */

import { describe, expect, it } from 'vitest'
import { admitsRequest, type WebAuthGate } from '../src/api-request-gate.ts'

function request(headers: Record<string, string | undefined>): { headers: Record<string, string | undefined> } {
  return { headers }
}

/** A seam stand-in: `required` reflects a mounted provider, `authenticate` a presented credential. */
function gate(options: { required: boolean; accepts?: string }): WebAuthGate {
  return {
    required: options.required,
    authenticate: (candidate) => {
      const headers = candidate.headers as Record<string, string | undefined>
      return Promise.resolve(
        options.accepts !== undefined && headers['x-proof'] === options.accepts
          ? { subject: 'verified-subject' }
          : undefined,
      )
    },
  }
}

const LOOPBACK = { host: '127.0.0.1:3080' }
const DECLARED = { host: 'harness.example:3080' }
const UNDECLARED = { host: 'evil.example:3080' }
const TRUSTED = ['harness.example:3080']

describe('admitsRequest without an authentication seam', () => {
  it('admits exactly what the authority fence admits', async () => {
    // This is the shipped default: no seam mounted, so behavior must be
    // indistinguishable from the fence alone.
    expect(await admitsRequest(request(LOOPBACK), 'trusted-host', TRUSTED, undefined)).toBe(true)
    expect(await admitsRequest(request(DECLARED), 'trusted-host', TRUSTED, undefined)).toBe(true)
    expect(await admitsRequest(request(UNDECLARED), 'trusted-host', TRUSTED, undefined)).toBe(false)
    expect(await admitsRequest(request(DECLARED), 'trusted-host', [], undefined)).toBe(false)
  })

  it('keeps the loopback authority pinned to the host machine', async () => {
    expect(await admitsRequest(request(LOOPBACK), 'loopback', TRUSTED, undefined)).toBe(true)
    expect(await admitsRequest(request(DECLARED), 'loopback', TRUSTED, undefined)).toBe(false)
    expect(await admitsRequest(request(UNDECLARED), 'loopback', TRUSTED, undefined)).toBe(false)
  })

  it('treats a mounted seam with no provider exactly as no seam at all', async () => {
    // The requirement follows the PROVIDERS, so a seam row without one must not
    // start refusing traffic the deployment expects to serve.
    const empty = gate({ required: false })
    expect(await admitsRequest(request(DECLARED), 'trusted-host', TRUSTED, empty)).toBe(true)
    expect(await admitsRequest(request(DECLARED), 'loopback', TRUSTED, empty)).toBe(false)
    expect(await admitsRequest(request(LOOPBACK), 'loopback', TRUSTED, empty)).toBe(true)
  })
})

describe('admitsRequest with authentication required', () => {
  const auth = gate({ required: true, accepts: 'good' })

  it('refuses an anonymous request from a declared authority', async () => {
    // The LAN case this feature exists for: the CLI derives LAN literals into
    // trustedHosts, so before authentication this request reached session.prompt.
    expect(await admitsRequest(request(DECLARED), 'trusted-host', TRUSTED, auth)).toBe(false)
  })

  it('admits a verified principal from a declared authority', async () => {
    expect(await admitsRequest(request({ ...DECLARED, 'x-proof': 'good' }), 'trusted-host', TRUSTED, auth)).toBe(true)
  })

  it('admits loopback without a credential, as before', async () => {
    // Loopback already implies running code as this process, so requiring a
    // password of it would protect nothing and would break local tooling.
    expect(await admitsRequest(request(LOOPBACK), 'trusted-host', TRUSTED, auth)).toBe(true)
    expect(await admitsRequest(request(LOOPBACK), 'loopback', TRUSTED, auth)).toBe(true)
  })

  it('opens the loopback-pinned plane to a verified principal', async () => {
    // The pin existed because trustedHosts is not authentication. With a
    // verified principal it is.
    expect(await admitsRequest(request({ ...DECLARED, 'x-proof': 'good' }), 'loopback', TRUSTED, auth)).toBe(true)
    expect(await admitsRequest(request(DECLARED), 'loopback', TRUSTED, auth)).toBe(false)
  })

  it('never lets a credential substitute for the authority fence', async () => {
    // Authentication is layered ON the rebinding defense, not in place of it: an
    // undeclared Host is refused however good the credential is, under either
    // authority.
    const proven = request({ ...UNDECLARED, 'x-proof': 'good' })
    expect(await admitsRequest(proven, 'trusted-host', TRUSTED, auth)).toBe(false)
    expect(await admitsRequest(proven, 'loopback', TRUSTED, auth)).toBe(false)
  })

  it('still refuses a cross-site marker from a verified principal', async () => {
    const crossSite = request({ ...DECLARED, 'x-proof': 'good', 'sec-fetch-site': 'cross-site' })
    expect(await admitsRequest(crossSite, 'trusted-host', TRUSTED, auth)).toBe(false)
    expect(await admitsRequest(crossSite, 'loopback', TRUSTED, auth)).toBe(false)
  })

  it('refuses a wrong credential exactly as it refuses none', async () => {
    expect(await admitsRequest(request({ ...DECLARED, 'x-proof': 'wrong' }), 'trusted-host', TRUSTED, auth)).toBe(false)
  })
})

/**
 * Behavior of the Cloudflare Access provider. Every key is generated in-process
 * and every key set is served by a local HTTP server, so the suite reaches no
 * network and pins no external fixture.
 */

import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { generateKeyPairSync, sign, type JsonWebKey, type KeyObject } from 'node:crypto'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import InvariantRegistry from '@deepseek-ai/dsh-invariants'
import WebAuth from '@deepseek-ai/dsh-host-web-auth'
import * as CloudflareInvariant from '../src/invariant.ts'
import { CloudflareAccessProvider } from '../src/provider.ts'
import { verifyToken } from '../src/jwt.ts'
import { apply, inject, name } from '../src/index.ts'

const ISSUER = 'https://team.cloudflareaccess.example'
const AUDIENCE = 'aud-tag-for-this-application'

/**
 * The suite's clock, advanced by cache-lifetime cases. It starts at real time so
 * the same minted tokens are valid both for providers reading this clock and for
 * the plugin-mounted provider, which reads `Date.now()`.
 */
let clock = Date.now()

/** Current test time in epoch seconds — the basis for every minted claim. */
function nowSeconds(): number {
  return Math.floor(clock / 1000)
}

/** One in-process signing key plus the public JWK a key set would publish. */
interface TestKey {
  privateKey: KeyObject
  jwk: JsonWebKey & { kid: string }
}

function makeKey(kid: string): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } }
}

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

/** Mint a compact JWT, signing whatever header and claims the caller asked for. */
function mintToken(
  key: TestKey,
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
): string {
  const signingInput = `${base64url({ alg: 'RS256', kid: key.jwk.kid, ...header })}.${base64url({
    iss: ISSUER,
    aud: [AUDIENCE],
    email: 'operator@example.com',
    sub: 'subject-id',
    exp: nowSeconds() + 600,
    ...claims,
  })}`
  const signature = sign('RSA-SHA256', Buffer.from(signingInput, 'ascii'), key.privateKey)
  return `${signingInput}.${signature.toString('base64url')}`
}

/** A local key-set endpoint whose body and status the test controls, counting requests. */
interface KeySetServer {
  url: string
  requests: () => number
  serve: (body: unknown, status?: number) => void
  close: () => Promise<void>
}

async function startKeySetServer(initial: unknown): Promise<KeySetServer> {
  let body: unknown = initial
  let status = 200
  let requests = 0
  const server: Server = createServer((_request, response) => {
    requests += 1
    response.writeHead(status, { 'content-type': 'application/json' })
    response.end(JSON.stringify(body))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${String(port)}/cdn-cgi/access/certs`,
    requests: () => requests,
    serve: (next, nextStatus = 200) => { body = next; status = nextStatus },
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error === undefined) resolve()
        else reject(error)
      })
    }),
  }
}

let key: TestKey
let keySet: KeySetServer
let rejections: string[]

beforeEach(async () => {
  key = makeKey('key-1')
  keySet = await startKeySetServer({ keys: [key.jwk] })
  rejections = []
  clock = Date.now()
})

afterEach(async () => {
  await keySet.close()
})

function provider(): CloudflareAccessProvider {
  return new CloudflareAccessProvider({
    issuer: ISSUER,
    audience: AUDIENCE,
    certsUrl: keySet.url,
    onRejected: reason => rejections.push(reason),
    now: () => clock,
  })
}

describe('Cloudflare Access token verification', () => {
  it('accepts a token signed by a published key and names the user', async () => {
    expect(await provider().verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(key) } }))
      .toEqual({ provider: 'cloudflare-access', subject: 'operator@example.com' })
    expect(rejections).toEqual([])
  })

  it('falls back to sub when the token carries no email', async () => {
    const token = mintToken(key, { email: undefined })
    expect(await provider().verifyRequest({ headers: { 'cf-access-jwt-assertion': token } }))
      .toMatchObject({ subject: 'subject-id' })
  })

  it('accepts the browser cookie, preferring the assertion header when both are present', async () => {
    const subject = provider()
    expect(await subject.verifyRequest({ headers: { cookie: `CF_Authorization=${mintToken(key)}` } }))
      .toMatchObject({ subject: 'operator@example.com' })
    // A valid header alongside a junk cookie must still verify.
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': mintToken(key), cookie: 'CF_Authorization=nonsense' },
    })).toMatchObject({ subject: 'operator@example.com' })
  })

  it('treats a request with no token as simply unauthenticated', async () => {
    expect(await provider().verifyRequest({ headers: {} })).toBeUndefined()
    expect(rejections).toEqual([])
  })

  it('refuses a token minted for another application in the same team', async () => {
    const token = mintToken(key, { aud: ['some-other-application'] })
    expect(await provider().verifyRequest({ headers: { 'cf-access-jwt-assertion': token } })).toBeUndefined()
    expect(rejections.join()).toMatch(/audience/)
  })

  it('accepts a string aud that matches and refuses one that does not', async () => {
    const subject = provider()
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': mintToken(key, { aud: AUDIENCE }) },
    })).toMatchObject({ subject: 'operator@example.com' })
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': mintToken(key, { aud: 'other' }) },
    })).toBeUndefined()
    // A missing aud is not a wildcard.
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': mintToken(key, { aud: undefined }) },
    })).toBeUndefined()
  })

  it('refuses another issuer, an expired token, and one not yet valid', async () => {
    const subject = provider()
    for (const [claims, expected] of [
      [{ iss: 'https://attacker.example' }, /issuer/],
      [{ exp: nowSeconds() - 3600 }, /expired/],
      [{ exp: undefined }, /numeric exp/],
      [{ nbf: nowSeconds() + 3600 }, /not yet valid/],
      [{ email: undefined, sub: undefined }, /neither email nor sub/],
    ] as const) {
      rejections.length = 0
      expect(await subject.verifyRequest({
        headers: { 'cf-access-jwt-assertion': mintToken(key, claims) },
      })).toBeUndefined()
      expect(rejections.join()).toMatch(expected)
    }
  })

  it('tolerates a token just inside the clock-skew window', async () => {
    const subject = provider()
    // Thirty seconds past expiry is within the one-minute allowance.
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': mintToken(key, { exp: nowSeconds() - 30 }) },
    })).toMatchObject({ subject: 'operator@example.com' })
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': mintToken(key, { nbf: nowSeconds() + 30 }) },
    })).toMatchObject({ subject: 'operator@example.com' })
  })

  it('refuses a token signed by a key the team never published', async () => {
    const foreign = makeKey('key-1')
    expect(await provider().verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(foreign) } }))
      .toBeUndefined()
    expect(rejections.join()).toMatch(/signature/)
  })

  it('refuses a tampered payload', async () => {
    const [header, , signature] = mintToken(key).split('.') as [string, string, string]
    const forged = `${header}.${base64url({
      iss: ISSUER, aud: [AUDIENCE], email: 'attacker@example.com', exp: nowSeconds() + 600,
    })}.${signature}`
    expect(await provider().verifyRequest({ headers: { 'cf-access-jwt-assertion': forged } })).toBeUndefined()
    expect(rejections.join()).toMatch(/signature/)
  })

  it('pins the algorithm instead of trusting the token header', async () => {
    const subject = provider()
    // `none` would skip verification, and an HMAC name would invite signing with
    // the public key as a shared secret. Both are refused on the header alone.
    for (const alg of ['none', 'HS256', 'RS512', undefined]) {
      rejections.length = 0
      expect(await subject.verifyRequest({
        headers: { 'cf-access-jwt-assertion': mintToken(key, {}, { alg }) },
      })).toBeUndefined()
      expect(rejections.join()).toMatch(/algorithm/)
    }
  })

  it('refuses structurally malformed tokens', async () => {
    const subject = provider()
    for (const token of ['', 'one.two', 'a.b.c.d', `${base64url({ alg: 'RS256' })}.@@@.sig`]) {
      expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': token } })).toBeUndefined()
    }
    // A header that is valid base64url but not JSON is reported, not thrown.
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': `${Buffer.from('nope').toString('base64url')}.x.y` },
    })).toBeUndefined()
    expect(rejections.join()).toMatch(/not JSON|three-segment/)
  })
})

describe('Cloudflare Access key set', () => {
  it('fetches once and serves later requests from cache', async () => {
    const subject = provider()
    for (let call = 0; call < 4; call += 1) {
      expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(key) } }))
        .toMatchObject({ subject: 'operator@example.com' })
    }
    expect(keySet.requests()).toBe(1)
  })

  it('coalesces concurrent first requests onto one fetch', async () => {
    const subject = provider()
    const token = mintToken(key)
    const results = await Promise.all(Array.from({ length: 5 }, () =>
      subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': token } })))
    expect(results.every(result => result?.subject === 'operator@example.com')).toBe(true)
    expect(keySet.requests()).toBe(1)
  })

  it('refetches after the cache lifetime, and a withdrawn key stops verifying', async () => {
    const subject = provider()
    const token = mintToken(key)
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': token } })).toBeDefined()

    const rotated = makeKey('key-2')
    keySet.serve({ keys: [rotated.jwk] })
    clock += 60 * 60 * 1000
    // The replacement is wholesale: the old key is gone, not merged.
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': token } })).toBeUndefined()
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(rotated) } }))
      .toMatchObject({ subject: 'operator@example.com' })
    expect(keySet.requests()).toBe(2)
  })

  it('refetches once for an unknown key id, then rate-limits further unknown ids', async () => {
    const subject = provider()
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(key) } })).toBeDefined()
    expect(keySet.requests()).toBe(1)

    // A rotation the cache has not seen: one refetch is warranted.
    const rotated = makeKey('key-2')
    keySet.serve({ keys: [rotated.jwk] })
    clock += 61 * 1000
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(rotated) } }))
      .toMatchObject({ subject: 'operator@example.com' })
    expect(keySet.requests()).toBe(2)

    // Forged key ids inside the cooldown must not become outbound traffic.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const forged = makeKey(`forged-${String(attempt)}`)
      expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(forged) } }))
        .toBeUndefined()
    }
    expect(keySet.requests()).toBe(2)
    expect(rejections.join()).toMatch(/no signing key for kid/)
  })

  it('identifies a single-key set for a token naming no key id, and refuses when ambiguous', async () => {
    const subject = provider()
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': mintToken(key, {}, { kid: undefined }) },
    })).toMatchObject({ subject: 'operator@example.com' })

    keySet.serve({ keys: [key.jwk, makeKey('key-2').jwk] })
    clock += 60 * 60 * 1000
    expect(await subject.verifyRequest({
      headers: { 'cf-access-jwt-assertion': mintToken(key, {}, { kid: undefined }) },
    })).toBeUndefined()
    expect(rejections.join()).toMatch(/no signing key for kid undefined/)
  })

  it('answers unauthenticated — never an error — when the key set is unreachable or empty', async () => {
    const subject = provider()
    keySet.serve({ keys: [] }, 500)
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(key) } }))
      .toBeUndefined()
    expect(rejections.join()).toMatch(/answered 500/)

    rejections.length = 0
    keySet.serve({ keys: [] })
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(key) } }))
      .toBeUndefined()
    expect(rejections.join()).toMatch(/no usable keys/)

    // Keys without a kid are unusable, which is the same empty-set outcome.
    rejections.length = 0
    keySet.serve({})
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(key) } }))
      .toBeUndefined()
    expect(rejections.join()).toMatch(/no usable keys/)
  })

  it('reports a published key that is not a usable JWK', async () => {
    const subject = provider()
    // Present under the right kid but missing the RSA modulus and exponent, so
    // key import fails rather than signature verification.
    keySet.serve({ keys: [{ kid: key.jwk.kid, kty: 'RSA' }] })
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(key) } }))
      .toBeUndefined()
    expect(rejections.join()).toMatch(/not a usable JWK/)
  })

  it('ignores a published key with no key id, which leaves the set unusable', async () => {
    const subject = provider()
    keySet.serve({ keys: [{ ...key.jwk, kid: undefined }] })
    expect(await subject.verifyRequest({ headers: { 'cf-access-jwt-assertion': mintToken(key) } }))
      .toBeUndefined()
    expect(rejections.join()).toMatch(/no usable keys/)
  })
})

describe('verifyToken called directly', () => {
  it('re-checks the algorithm, so a caller cannot pair one token\'s key id with another token', () => {
    // `tokenKeyId` pinned `alg` for the token whose key was resolved; this
    // function must not trust that a different token was pinned too.
    expect(() => verifyToken(
      mintToken(key, {}, { alg: 'none' }),
      key.jwk,
      AUDIENCE,
      ISSUER,
      nowSeconds(),
    )).toThrow(/algorithm/)
  })
})

describe('Cloudflare Access plugin', () => {
  it('registers the provider and derives the issuer and key-set URL from the team domain', async () => {
    const ctx = new Context()
    await ctx.plugin(WebAuth)
    const fiber = ctx.plugin({ name, inject: [...inject], apply }, {
      teamDomain: 'team.cloudflareaccess.example',
      audience: AUDIENCE,
      certsUrl: keySet.url,
    })
    await fiber.await()
    expect(ctx.webAuth.required).toBe(true)
    // A request provider adds no sign-in page: nothing here judges a secret.
    expect(ctx.webAuth.interactive).toBe(false)
    // The derived issuer is the team domain's origin, which is what the minted
    // fixture tokens claim.
    expect(await ctx.webAuth.authenticate({ headers: { 'cf-access-jwt-assertion': mintToken(key) } }))
      .toEqual({ provider: 'cloudflare-access', subject: 'operator@example.com' })

    await fiber.dispose()
    expect(ctx.webAuth.required).toBe(false)
    await ctx.fiber.dispose()
  })

  it('derives the standard key-set path when none is configured, and logs a rejected token', async () => {
    const ctx = new Context()
    await ctx.plugin(WebAuth)
    // No certsUrl: the provider derives Cloudflare's standard path from the team
    // domain. A structurally invalid token is refused before any fetch, so this
    // exercises the derived default and the logger hook without leaving the host.
    const fiber = ctx.plugin({ name, inject: [...inject], apply }, {
      teamDomain: 'team.cloudflareaccess.example',
      audience: AUDIENCE,
    })
    await fiber.await()
    expect(await ctx.webAuth.authenticate({ headers: { 'cf-access-jwt-assertion': 'not-a-jwt' } }))
      .toBeUndefined()
    await fiber.dispose()
    await ctx.fiber.dispose()
  })

  it('fails the load on a team domain that is not a bare hostname', async () => {
    const ctx = new Context()
    await ctx.plugin(WebAuth)
    for (const teamDomain of ['https://team.cloudflareaccess.com', 'team.cloudflareaccess.com/path', 'a b']) {
      const fiber = ctx.plugin({ name, inject: [...inject], apply }, { teamDomain, audience: AUDIENCE })
      await expect(fiber).rejects.toThrow(/must be a bare hostname/)
    }
    expect(ctx.webAuth.required).toBe(false)
    await ctx.fiber.dispose()
  })

  it('reserves package ownership without installing a session check', async () => {
    const ctx = new Context()
    await ctx.plugin(InvariantRegistry)
    await expect(ctx.plugin(CloudflareInvariant).then(() => undefined)).resolves.toBeUndefined()
    await ctx.fiber.dispose()
  })
})

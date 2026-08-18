/** Behavior of the web-authentication seam: cookie encoding, session records, provider registry, and sign-in. */

import { Context } from '@deepseek-ai/cordis'
import { describe, expect, it } from 'vitest'
import InvariantRegistry from '@deepseek-ai/dsh-invariants'
import * as WebAuthInvariant from '../src/invariant.ts'
import {
  clearedSessionCookie,
  header,
  isSecureCookieRequest,
  readCookie,
  readSessionToken,
  SESSION_COOKIE_NAME,
  sessionCookie,
} from '../src/cookie.ts'
import { SignInSessions } from '../src/sessions.ts'
import { LOGIN_PAGE_HTML } from '../src/login-page.ts'
import { SIGN_IN_PATH } from '../src/paths.ts'
import WebAuth, { type WebAuthProvider, type WebAuthSignInOutcome } from '../src/index.ts'

/** One provider verifying a fixed secret, with a recorded call log. */
function secretProvider(
  id: string,
  accepted: string,
  calls: string[],
  outcome?: WebAuthSignInOutcome,
): WebAuthProvider {
  return {
    id,
    verifySecret: (secret) => {
      calls.push(id)
      if (outcome !== undefined) return Promise.resolve(outcome)
      return Promise.resolve(secret === accepted
        ? { outcome: 'verified', identity: { provider: id, subject: `${id}-subject` } }
        : { outcome: 'rejected' })
    },
  }
}

/** One provider verifying a header credential. */
function headerProvider(id: string, header: string, value: string): WebAuthProvider {
  return {
    id,
    verifyRequest: request => Promise.resolve(
      (request.headers as Record<string, string>)[header] === value
        ? { provider: id, subject: `${id}-subject` }
        : undefined,
    ),
  }
}

async function mounted(config?: { sessionTtlSeconds?: number; cookieSecure?: 'auto' | 'always' | 'never' }): Promise<{
  ctx: Context
  webAuth: WebAuth
  dispose: () => Promise<void>
}> {
  const ctx = new Context()
  const fiber = ctx.plugin(WebAuth, config)
  await fiber.await()
  return { ctx, webAuth: ctx.webAuth, dispose: () => fiber.dispose() }
}

describe('sign-in cookie', () => {
  it('carries every attribute that makes cookie possession evidence of a first-party context', () => {
    const cookie = sessionCookie('token-value', 600, false)
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=token-value`)
    // HttpOnly keeps script from reading it; SameSite=Strict is what stops a
    // cross-site or DNS-rebound page from having it attached at all.
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('SameSite=Strict')
    expect(cookie).toContain('Path=/')
    expect(cookie).toContain('Max-Age=600')
    expect(cookie).not.toContain('Secure')
    expect(sessionCookie('token-value', 600, true)).toContain('Secure')
  })

  it('clears with the issued attributes so the browser drops the pair instead of keeping both', () => {
    const cleared = clearedSessionCookie(true)
    expect(cleared).toContain(`${SESSION_COOKIE_NAME}=;`)
    expect(cleared).toContain('Max-Age=0')
    expect(cleared).toContain('Path=/')
    expect(cleared).toContain('HttpOnly')
    expect(cleared).toContain('SameSite=Strict')
    expect(cleared).toContain('Secure')
  })

  it('decides Secure from the deployment policy, trusting a forwarding hop only to add it', () => {
    expect(isSecureCookieRequest('always', {})).toBe(true)
    expect(isSecureCookieRequest('never', { 'x-forwarded-proto': 'https' })).toBe(false)
    expect(isSecureCookieRequest('auto', {})).toBe(false)
    expect(isSecureCookieRequest('auto', { 'x-forwarded-proto': 'https' })).toBe(true)
    expect(isSecureCookieRequest('auto', { 'x-forwarded-proto': 'http' })).toBe(false)
    // A proxy chain reports the ORIGINAL scheme first.
    expect(isSecureCookieRequest('auto', { 'x-forwarded-proto': 'https, http' })).toBe(true)
    expect(isSecureCookieRequest('auto', new Headers({ 'x-forwarded-proto': 'HTTPS' }))).toBe(true)
  })

  it('reads one cookie out of a shared header and ignores neighbours', () => {
    const headers = { cookie: `other=1; ${SESSION_COOKIE_NAME}=wanted; trailing=2` }
    expect(readSessionToken(headers)).toBe('wanted')
    expect(readCookie(headers, 'other')).toBe('1')
    expect(readCookie(headers, 'absent')).toBeUndefined()
    expect(readSessionToken({})).toBeUndefined()
    // An empty value is not a token; a malformed pair must not derail the scan.
    expect(readSessionToken({ cookie: `${SESSION_COOKIE_NAME}=` })).toBeUndefined()
    expect(readSessionToken({ cookie: `novalue; ${SESSION_COOKIE_NAME}=found` })).toBe('found')
    // A name that merely ends with the cookie name must not match.
    expect(readSessionToken({ cookie: `not_${SESSION_COOKIE_NAME}=x` })).toBeUndefined()
    expect(readSessionToken(new Headers({ cookie: `${SESSION_COOKIE_NAME}=via-fetch` }))).toBe('via-fetch')
    expect(readSessionToken(new Headers())).toBeUndefined()
    // A repeated header arrives as an array. No header this seam reads is
    // legitimately repeated, so the array form counts as absent rather than
    // being joined into a value a provider might trust.
    expect(header({ 'x-access-assertion': ['first', 'second'] }, 'x-access-assertion')).toBeUndefined()
    expect(header({ 'x-access-assertion': 'only' }, 'x-access-assertion')).toBe('only')
  })
})

describe('SignInSessions', () => {
  it('resolves an issued token, forgets it on revoke, and never returns an expired record', () => {
    let now = 1_000_000
    const sessions = new SignInSessions(60, () => now)
    const token = sessions.issue({ provider: 'p', subject: 's' })
    expect(sessions.resolve(token)).toEqual({ provider: 'p', subject: 's' })
    expect(sessions.resolve('some-other-token')).toBeUndefined()

    now += 60_000
    expect(sessions.resolve(token)).toBeUndefined()

    const second = sessions.issue({ provider: 'p', subject: 's2' })
    sessions.revoke(second)
    expect(sessions.resolve(second)).toBeUndefined()
    // Revoking an unknown token is a no-op, not a throw.
    expect(() => { sessions.revoke('unknown') }).not.toThrow()
  })

  it('issues distinct high-entropy tokens and drops everything on clear', () => {
    const sessions = new SignInSessions(60)
    const tokens = new Set(Array.from({ length: 16 }, () => sessions.issue({ provider: 'p', subject: 's' })))
    expect(tokens.size).toBe(16)
    // 32 random bytes, base64url: 43 characters, no padding.
    for (const token of tokens) expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const sample = [...tokens][0]!
    sessions.clear()
    expect(sessions.resolve(sample)).toBeUndefined()
  })

  it('bounds the table, shedding expired records first and the oldest live one otherwise', () => {
    let now = 1_000_000
    const sessions = new SignInSessions(60, () => now)
    const expiring = sessions.issue({ provider: 'p', subject: 'expiring' })
    now += 60_000
    // Fill past the ceiling: the expired record above is reclaimed silently.
    const live = Array.from({ length: 128 }, (_unused, index) =>
      sessions.issue({ provider: 'p', subject: `live-${String(index)}` }))
    expect(sessions.resolve(expiring)).toBeUndefined()
    // One more eviction now has only live records to choose from, and takes the
    // oldest, so the newest session — the operator's own — always survives.
    const newest = sessions.issue({ provider: 'p', subject: 'newest' })
    expect(sessions.resolve(live[0]!)).toBeUndefined()
    expect(sessions.resolve(newest)).toEqual({ provider: 'p', subject: 'newest' })
    expect(sessions.resolve(live[127]!)).toEqual({ provider: 'p', subject: 'live-127' })
  })
})

describe('WebAuth provider registry', () => {
  it('requires no authentication until a provider is mounted', async () => {
    const { webAuth, dispose } = await mounted()
    expect(webAuth.required).toBe(false)
    expect(webAuth.interactive).toBe(false)
    expect(await webAuth.authenticate({ headers: {} })).toBeUndefined()
    expect(await webAuth.status({ headers: {} }))
      .toEqual({ required: false, authenticated: false, interactive: false })
    await dispose()
  })

  it('refuses a provider with no verification surface, which would gate without ever admitting', async () => {
    const { webAuth, dispose } = await mounted()
    expect(() => webAuth.register({ id: 'inert' }))
      .toThrow(/supplies no verification surface/)
    expect(webAuth.required).toBe(false)
    await dispose()
  })

  it('refuses a duplicate id', async () => {
    const { webAuth, dispose } = await mounted()
    webAuth.register(headerProvider('dup', 'x-token', 'ok'))
    expect(() => webAuth.register(headerProvider('dup', 'x-other', 'ok')))
      .toThrow(/already registered/)
    await dispose()
  })

  it('unregisters through the disposer the registry returns, not only with the fiber', async () => {
    const { webAuth, dispose } = await mounted()
    const remove = webAuth.register(headerProvider('removable', 'x-token', 'ok'))
    expect(webAuth.required).toBe(true)
    remove()
    expect(webAuth.required).toBe(false)
    expect(await webAuth.authenticate({ headers: { 'x-token': 'ok' } })).toBeUndefined()
    await dispose()
  })

  it('unregisters with the calling fiber, so the requirement follows the providers', async () => {
    const { ctx, webAuth, dispose } = await mounted()
    const child = ctx.plugin({
      inject: ['webAuth'],
      apply: (inner: Context) => { inner.webAuth.register(headerProvider('scoped', 'x-token', 'ok')) },
    })
    await child.await()
    expect(webAuth.required).toBe(true)
    await child.dispose()
    expect(webAuth.required).toBe(false)
    expect(await webAuth.authenticate({ headers: { 'x-token': 'ok' } })).toBeUndefined()
    await dispose()
  })

  it('reports interactive only for a provider that judges submitted secrets', async () => {
    const { webAuth, dispose } = await mounted()
    webAuth.register(headerProvider('request-only', 'x-token', 'ok'))
    expect(webAuth.required).toBe(true)
    expect(webAuth.interactive).toBe(false)
    webAuth.register(secretProvider('interactive', 'right', []))
    expect(webAuth.interactive).toBe(true)
    await dispose()
  })
})

describe('WebAuth request verification', () => {
  it('honors a request credential and rejects a wrong one', async () => {
    const { webAuth, dispose } = await mounted()
    webAuth.register(headerProvider('header', 'x-token', 'ok'))
    expect(await webAuth.authenticate({ headers: { 'x-token': 'ok' } }))
      .toEqual({ provider: 'header', subject: 'header-subject' })
    expect(await webAuth.authenticate({ headers: { 'x-token': 'wrong' } })).toBeUndefined()
    expect(await webAuth.authenticate({ headers: {} })).toBeUndefined()
    await dispose()
  })

  it('tries each request provider until one verifies', async () => {
    const { webAuth, dispose } = await mounted()
    webAuth.register(headerProvider('first', 'x-first', 'ok'))
    webAuth.register(headerProvider('second', 'x-second', 'ok'))
    expect(await webAuth.authenticate({ headers: { 'x-second': 'ok' } }))
      .toEqual({ provider: 'second', subject: 'second-subject' })
    await dispose()
  })

  it('resolves a live session cookie without consulting any provider', async () => {
    const { webAuth, dispose } = await mounted()
    const calls: string[] = []
    webAuth.register(secretProvider('password', 'right', calls))
    const signedIn = await webAuth.signIn('right', {}, { headers: {} })
    expect(signedIn.outcome).toBe('verified')
    if (signedIn.outcome !== 'verified') throw new Error('unreachable')
    const token = /dsh_web_auth=([^;]+)/.exec(signedIn.setCookie)?.[1]
    expect(token).toBeDefined()
    calls.length = 0

    const identity = await webAuth.authenticate({ headers: { cookie: `${SESSION_COOKIE_NAME}=${token!}` } })
    expect(identity).toEqual({ provider: 'password', subject: 'password-subject' })
    expect(calls).toEqual([])
    expect(await webAuth.status({ headers: { cookie: `${SESSION_COOKIE_NAME}=${token!}` } }))
      .toEqual({ required: true, authenticated: true, interactive: true })
    await dispose()
  })

  it('falls through to providers when the presented cookie names no live session', async () => {
    const { webAuth, dispose } = await mounted()
    webAuth.register(headerProvider('header', 'x-token', 'ok'))
    expect(await webAuth.authenticate({
      headers: { cookie: `${SESSION_COOKIE_NAME}=stale`, 'x-token': 'ok' },
    })).toEqual({ provider: 'header', subject: 'header-subject' })
    await dispose()
  })
})

describe('WebAuth sign-in', () => {
  it('reports unsupported when no mounted provider judges secrets', async () => {
    const { webAuth, dispose } = await mounted()
    webAuth.register(headerProvider('header', 'x-token', 'ok'))
    expect(await webAuth.signIn('anything', {}, { headers: {} })).toEqual({ outcome: 'unsupported' })
    await dispose()
  })

  it('rejects a wrong secret after every judging provider has seen it', async () => {
    const { webAuth, dispose } = await mounted()
    const calls: string[] = []
    webAuth.register(secretProvider('a', 'secret-a', calls))
    webAuth.register(secretProvider('b', 'secret-b', calls))
    expect(await webAuth.signIn('secret-b', {}, { headers: {} })).toMatchObject({ outcome: 'verified' })
    expect(calls).toEqual(['a', 'b'])
    calls.length = 0
    expect(await webAuth.signIn('neither', {}, { headers: {} })).toEqual({ outcome: 'rejected' })
    expect(calls).toEqual(['a', 'b'])
    await dispose()
  })

  it('stops at a lockout so a second provider cannot be used to keep guessing', async () => {
    const { webAuth, dispose } = await mounted()
    const calls: string[] = []
    webAuth.register(secretProvider('locking', 'unused', calls, { outcome: 'locked', retryAfterSeconds: 42 }))
    webAuth.register(secretProvider('permissive', 'guess', calls))
    expect(await webAuth.signIn('guess', {}, { headers: {} }))
      .toEqual({ outcome: 'locked', retryAfterSeconds: 42 })
    expect(calls).toEqual(['locking'])
    await dispose()
  })

  it('passes the submitting client to the provider so a lockout can key on it', async () => {
    const { webAuth, dispose } = await mounted()
    const seen: (string | undefined)[] = []
    webAuth.register({
      id: 'recording',
      verifySecret: (_secret, client) => {
        seen.push(client.address)
        return Promise.resolve({ outcome: 'rejected' })
      },
    })
    await webAuth.signIn('x', { address: '10.0.0.9' }, { headers: {} })
    await webAuth.signIn('x', {}, { headers: {} })
    expect(seen).toEqual(['10.0.0.9', undefined])
    await dispose()
  })

  it('falls back to its schema defaults when constructed without config', async () => {
    // The Loader resolves defaults, but a hand-built context may pass none, so
    // the class carries the same values rather than producing NaN or undefined.
    const ctx = new Context()
    const webAuth = new WebAuth(ctx)
    webAuth.register(secretProvider('password', 'right', []))
    const result = await webAuth.signIn('right', {}, { headers: { 'x-forwarded-proto': 'https' } })
    if (result.outcome !== 'verified') throw new Error('expected verification')
    expect(result.setCookie).toContain(`Max-Age=${String(12 * 60 * 60)}`)
    // The default policy is `auto`, which reads the forwarding hop above.
    expect(result.setCookie).toContain('Secure')
    await ctx.fiber.dispose()
  })

  it('issues a cookie whose lifetime matches the configured session and the Secure policy', async () => {
    const { webAuth, dispose } = await mounted({ sessionTtlSeconds: 900, cookieSecure: 'always' })
    webAuth.register(secretProvider('password', 'right', []))
    const result = await webAuth.signIn('right', {}, { headers: {} })
    if (result.outcome !== 'verified') throw new Error('expected verification')
    expect(result.setCookie).toContain('Max-Age=900')
    expect(result.setCookie).toContain('Secure')
    expect(result.identity).toEqual({ provider: 'password', subject: 'password-subject' })
    await dispose()
  })

  it('revokes on sign-out and clears the cookie even when none was live', async () => {
    const { webAuth, dispose } = await mounted()
    webAuth.register(secretProvider('password', 'right', []))
    const signedIn = await webAuth.signIn('right', {}, { headers: {} })
    if (signedIn.outcome !== 'verified') throw new Error('expected verification')
    const token = /dsh_web_auth=([^;]+)/.exec(signedIn.setCookie)![1]!
    const cookieRequest = { headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` } }

    expect(webAuth.signOut(cookieRequest).setCookie).toContain('Max-Age=0')
    expect(await webAuth.authenticate(cookieRequest)).toBeUndefined()
    expect(webAuth.signOut({ headers: {} }).setCookie).toContain('Max-Age=0')
    await dispose()
  })

  it('drops every session when the seam is disposed', async () => {
    const { webAuth, dispose } = await mounted()
    webAuth.register(secretProvider('password', 'right', []))
    const signedIn = await webAuth.signIn('right', {}, { headers: {} })
    if (signedIn.outcome !== 'verified') throw new Error('expected verification')
    const token = /dsh_web_auth=([^;]+)/.exec(signedIn.setCookie)![1]!
    await dispose()
    expect(await webAuth.authenticate({ headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` } })).toBeUndefined()
  })
})

describe('sign-in page', () => {
  it('posts to this package\'s own sign-in path and loads no external resource', () => {
    expect(LOGIN_PAGE_HTML).toContain(JSON.stringify(SIGN_IN_PATH))
    // Everything the page needs is inline: no src/href fetches an origin.
    expect(LOGIN_PAGE_HTML).not.toMatch(/(?:src|href)="[^"]*\/\//)
    expect(LOGIN_PAGE_HTML).toContain('type="password"')
  })
})

describe('web-auth invariant companion', () => {
  it('reserves package ownership without installing a session check', async () => {
    const ctx = new Context()
    await ctx.plugin(InvariantRegistry)
    await expect(ctx.plugin(WebAuthInvariant).then(() => undefined)).resolves.toBeUndefined()
    await ctx.fiber.dispose()
  })
})

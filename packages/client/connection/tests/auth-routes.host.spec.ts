/**
 * The browser sign-in surface and the authenticated `/api` fence, over a real
 * bound HTTP server with a real `webAuth` seam and a real password provider.
 * Host headers are spoofed the way a LAN or tunnelled client's browser sends
 * them, so the assertions exercise the parse the server actually performs.
 */

import { mkdtemp, rm } from 'node:fs/promises'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ApiProxy } from '@deepseek-ai/dsh-host-apiproxy/api'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import WebAuth, { LOGIN_PATH, SIGN_IN_PATH, SIGN_OUT_PATH, STATUS_PATH } from '@deepseek-ai/dsh-host-web-auth'
import * as PasswordProvider from '@deepseek-ai/dsh-host-web-auth-password'
import { API_PATH, apply, inject } from '../src/index.ts'

const DECLARED_AUTHORITY = 'harness.example'

interface Answer {
  status: number
  headers: Record<string, string | string[] | undefined>
  body: string
}

interface Harness {
  port: number
  password: string
  call: (options: {
    path: string
    host?: string
    method?: 'GET' | 'POST'
    cookie?: string
    contentType?: string | null
    body?: string
  }) => Promise<Answer>
  dispose: () => Promise<void>
}

let root: string
let harness: Harness | undefined

/** Boot webserver + webAuth + password provider + the connection carrier. */
async function launch(options: { withAuth?: boolean; interactive?: boolean; withShell?: boolean } = {}): Promise<Harness> {
  const printed: string[] = []
  const log = vi.spyOn(console, 'log').mockImplementation((line: unknown) => { printed.push(String(line)) })
  const ctx = new Context()
  try {
    await ctx.plugin(WebServer, { host: '127.0.0.1', port: 0 })
    ctx.provide('apiProxy', {} as ApiProxy)
    // Stands in for the frontend's fallback seat, so a test can tell "the shell
    // was served" from "the gate answered".
    if (options.withShell === true) {
      ctx.webServer.registerFallback((_req, res) => {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        res.end('<!doctype html><title>shell</title>')
      })
    }
    if (options.withAuth !== false) {
      await ctx.plugin(WebAuth, { cookieSecure: 'never' })
      if (options.interactive === false) {
        // A request-credential-only deployment: authentication is required, but
        // no mounted provider judges a submitted secret.
        ctx.webAuth.register({
          id: 'header-only',
          verifyRequest: request => Promise.resolve(
            (request.headers as Record<string, string | undefined>)['x-proof'] === 'good'
              ? { provider: 'header-only', subject: 'proxy-user' }
              : undefined,
          ),
        })
      } else {
        await ctx.plugin(PasswordProvider, { file: join(root, 'password.json'), maxAttempts: 3, lockoutSeconds: 60 })
      }
    }
    const fiber = ctx.plugin({ inject: [...inject], apply }, { trustedHosts: [DECLARED_AUTHORITY] })
    await fiber.await()
    const port = ctx.webServer.port
    return {
      port,
      password: /Password: (\S+)/.exec(printed.join('\n'))?.[1] ?? '',
      call: ({ path, host, method = 'GET', cookie, contentType = 'application/json', body }) =>
        new Promise<Answer>((resolve, reject) => {
          const outgoing = httpRequest({
            host: '127.0.0.1',
            port,
            path,
            method,
            headers: {
              host: host ?? `127.0.0.1:${String(port)}`,
              ...cookie !== undefined && { cookie },
              ...contentType !== null && method === 'POST' && { 'content-type': contentType },
              ...body !== undefined && { 'content-length': String(Buffer.byteLength(body)) },
            },
          }, (response) => {
            const chunks: Buffer[] = []
            response.on('data', (chunk: Buffer) => chunks.push(chunk))
            response.on('end', () => {
              resolve({
                status: response.statusCode ?? 0,
                headers: response.headers,
                body: Buffer.concat(chunks).toString(),
              })
            })
          })
          outgoing.on('error', reject)
          if (body !== undefined) outgoing.write(body)
          outgoing.end()
        }),
      dispose: async () => { await ctx.fiber.dispose() },
    }
  } finally {
    log.mockRestore()
  }
}

/** Sign in and return the session cookie pair to replay. */
async function signIn(active: Harness, password = active.password): Promise<string> {
  const answer = await active.call({
    path: SIGN_IN_PATH,
    method: 'POST',
    body: JSON.stringify({ secret: password }),
  })
  expect(answer.status).toBe(200)
  const setCookie = answer.headers['set-cookie']
  const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie)?.split(';')[0]
  if (cookie === undefined) throw new Error('sign-in returned no cookie')
  return cookie
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'dsh-auth-routes-'))
})

afterEach(async () => {
  await harness?.dispose()
  harness = undefined
  await rm(root, { recursive: true, force: true })
})

describe('sign-in surface', () => {
  it('serves the login page and refuses an undeclared authority', async () => {
    harness = await launch()
    const page = await harness.call({ path: LOGIN_PATH })
    expect(page.status).toBe(200)
    expect(page.headers['content-type']).toBe('text/html; charset=utf-8')
    expect(page.headers['cache-control']).toBe('no-store')
    expect(page.headers['content-security-policy']).toContain("default-src 'none'")
    expect(page.body).toContain('type="password"')

    // The sign-in surface sits behind the same authority fence, so a rebound
    // page cannot use it as a password oracle.
    expect((await harness.call({ path: LOGIN_PATH, host: 'evil.example' })).status).toBe(403)
    expect((await harness.call({
      path: SIGN_IN_PATH, method: 'POST', host: 'evil.example', body: JSON.stringify({ secret: 'guess' }),
    })).status).toBe(403)
  })

  it('reports the authentication state before sign-in and after', async () => {
    harness = await launch()
    const anonymous = await harness.call({ path: STATUS_PATH })
    expect(JSON.parse(anonymous.body)).toEqual({ required: true, authenticated: false, interactive: true })

    const cookie = await signIn(harness)
    const signedIn = await harness.call({ path: STATUS_PATH, cookie })
    expect(JSON.parse(signedIn.body)).toEqual({ required: true, authenticated: true, interactive: true })
  })

  it('rejects a wrong password without saying what it accepts', async () => {
    harness = await launch()
    const answer = await harness.call({
      path: SIGN_IN_PATH, method: 'POST', body: JSON.stringify({ secret: 'not-the-password' }),
    })
    expect(answer.status).toBe(401)
    expect(JSON.parse(answer.body)).toEqual({ message: 'Incorrect password.' })
    expect(answer.headers['set-cookie']).toBeUndefined()
  })

  it('locks a client out after repeated failures and reports the wait', async () => {
    harness = await launch()
    for (let attempt = 0; attempt < 3; attempt += 1) {
      expect((await harness.call({
        path: SIGN_IN_PATH, method: 'POST', body: JSON.stringify({ secret: 'wrong' }),
      })).status).toBe(401)
    }
    // Even the correct password is refused while the lockout holds.
    const locked = await harness.call({
      path: SIGN_IN_PATH, method: 'POST', body: JSON.stringify({ secret: harness.password }),
    })
    expect(locked.status).toBe(429)
    expect(locked.headers['retry-after']).toBe('60')
    expect((JSON.parse(locked.body) as { message: string }).message).toMatch(/Too many failed attempts/)
  })

  it('requires a declared JSON body and the right method', async () => {
    harness = await launch()
    // The media-type fence: a cross-site "simple" POST cannot declare JSON, so
    // it is forced into a preflight this server never answers.
    expect((await harness.call({
      path: SIGN_IN_PATH, method: 'POST', contentType: 'text/plain', body: JSON.stringify({ secret: 'x' }),
    })).status).toBe(415)
    expect((await harness.call({
      path: SIGN_IN_PATH, method: 'POST', contentType: null, body: JSON.stringify({ secret: 'x' }),
    })).status).toBe(415)
    expect((await harness.call({ path: SIGN_IN_PATH, method: 'POST', body: 'not json' })).status).toBe(400)
    expect((await harness.call({ path: SIGN_IN_PATH, method: 'POST', body: JSON.stringify({}) })).status).toBe(400)
    expect((await harness.call({
      path: SIGN_IN_PATH, method: 'POST', body: JSON.stringify({ secret: 42 }),
    })).status).toBe(400)

    const wrongMethod = await harness.call({ path: SIGN_IN_PATH })
    expect(wrongMethod.status).toBe(405)
    expect(wrongMethod.headers.allow).toBe('POST')
    expect((await harness.call({ path: LOGIN_PATH, method: 'POST' })).status).toBe(405)
  })

  it('refuses a body larger than a submitted secret can be', async () => {
    harness = await launch()
    const answer = await harness.call({
      path: SIGN_IN_PATH, method: 'POST', body: JSON.stringify({ secret: 'x'.repeat(8192) }),
    })
    expect(answer.status).toBe(413)
  })

  it('issues a cookie whose attributes bind it to a first-party context', async () => {
    harness = await launch()
    const answer = await harness.call({
      path: SIGN_IN_PATH, method: 'POST', body: JSON.stringify({ secret: harness.password }),
    })
    const setCookie = answer.headers['set-cookie']
    const cookie = Array.isArray(setCookie) ? setCookie[0]! : String(setCookie)
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('SameSite=Strict')
    expect(cookie).toContain('Path=/')
    // cookieSecure: never — this harness is reached over plain HTTP in the test.
    expect(cookie).not.toContain('Secure')
  })
})

describe('the /api fence once authentication is required', () => {
  it('refuses an anonymous declared authority that the fence alone would admit', async () => {
    harness = await launch()
    // Without the seam this exact request reaches the carrier (see the
    // unauthenticated composition case below); with it, 403.
    const answer = await harness.call({ path: `${API_PATH}/session.list`, host: DECLARED_AUTHORITY })
    expect(answer.status).toBe(403)
    expect(answer.body).toBe('forbidden')
  })

  it('admits a signed-in browser and opens the loopback-pinned configuration plane', async () => {
    harness = await launch()
    const cookie = await signIn(harness)
    // 404 is the empty proxy's carrier answer: reaching it proves admission.
    expect((await harness.call({
      path: `${API_PATH}/session.list`, host: DECLARED_AUTHORITY, cookie,
    })).status).toBe(404)
    // The methods pinned to loopback because trustedHosts is not authentication.
    for (const method of ['settings.describe', 'settings.update', 'credentials.set', 'host.pickDirectory']) {
      expect([method, (await harness.call({
        path: `${API_PATH}/${method}`, host: DECLARED_AUTHORITY, cookie,
      })).status]).toEqual([method, 404])
      // The same method stays refused without the cookie.
      expect([method, (await harness.call({
        path: `${API_PATH}/${method}`, host: DECLARED_AUTHORITY,
      })).status]).toEqual([method, 403])
    }
  })

  it('keeps loopback reaching everything without a credential', async () => {
    harness = await launch()
    expect((await harness.call({ path: `${API_PATH}/session.list` })).status).toBe(404)
    expect((await harness.call({ path: `${API_PATH}/settings.describe` })).status).toBe(404)
  })

  it('never admits an undeclared authority, however good the credential', async () => {
    harness = await launch()
    const cookie = await signIn(harness)
    expect((await harness.call({
      path: `${API_PATH}/session.list`, host: 'evil.example', cookie,
    })).status).toBe(403)
  })

  it('stops admitting the cookie after sign-out', async () => {
    harness = await launch()
    const cookie = await signIn(harness)
    expect((await harness.call({
      path: `${API_PATH}/session.list`, host: DECLARED_AUTHORITY, cookie,
    })).status).toBe(404)

    const out = await harness.call({ path: SIGN_OUT_PATH, method: 'POST', cookie })
    expect(out.status).toBe(200)
    const cleared = out.headers['set-cookie']
    expect(Array.isArray(cleared) ? cleared[0]! : String(cleared)).toContain('Max-Age=0')

    // The record is revoked server-side, so replaying the cookie fails.
    expect((await harness.call({
      path: `${API_PATH}/session.list`, host: DECLARED_AUTHORITY, cookie,
    })).status).toBe(403)
  })
})

describe('a deployment whose only provider reads request credentials', () => {
  it('reports that it accepts no submitted secret, and admits the header credential', async () => {
    harness = await launch({ interactive: false })
    expect(JSON.parse((await harness.call({ path: STATUS_PATH })).body))
      .toEqual({ required: true, authenticated: false, interactive: false })

    const attempt = await harness.call({
      path: SIGN_IN_PATH, method: 'POST', body: JSON.stringify({ secret: 'anything' }),
    })
    expect(attempt.status).toBe(400)
    expect((JSON.parse(attempt.body) as { message: string }).message).toMatch(/accepts no submitted secret/)

    // The proxy-supplied credential is what admits a request here.
    expect((await harness.call({ path: `${API_PATH}/session.list`, host: DECLARED_AUTHORITY })).status).toBe(403)
  })
})

describe('a composition that mounts no authentication', () => {
  it('behaves exactly as before: declared authorities pass, the configuration plane stays loopback', async () => {
    harness = await launch({ withAuth: false })
    expect((await harness.call({ path: `${API_PATH}/session.list`, host: DECLARED_AUTHORITY })).status).toBe(404)
    expect((await harness.call({ path: `${API_PATH}/settings.describe`, host: DECLARED_AUTHORITY })).status).toBe(403)
    expect((await harness.call({ path: `${API_PATH}/settings.describe` })).status).toBe(404)
    // No seam, no sign-in surface: the routes do not exist at all.
    expect((await harness.call({ path: LOGIN_PATH })).status).toBe(404)
    expect((await harness.call({ path: STATUS_PATH })).status).toBe(404)
  })
})

describe('the app shell an anonymous browser reaches', () => {
  it('redirects a declared-authority navigation to the sign-in page', async () => {
    harness = await launch({ withShell: true })
    const answer = await harness.call({ path: '/', host: DECLARED_AUTHORITY })
    expect(answer.status).toBe(302)
    expect(answer.headers.location).toBe(LOGIN_PATH)
    expect(answer.headers['cache-control']).toBe('no-store')
    // The shell itself never went out.
    expect(answer.body).not.toContain('shell')
  })

  it('serves the shell over loopback without a credential', async () => {
    harness = await launch({ withShell: true })
    const answer = await harness.call({ path: '/' })
    expect(answer.status).toBe(200)
    expect(answer.body).toContain('shell')
  })

  it('serves the shell to a signed-in browser', async () => {
    harness = await launch({ withShell: true })
    const cookie = await signIn(harness)
    const answer = await harness.call({ path: '/', host: DECLARED_AUTHORITY, cookie })
    expect(answer.status).toBe(200)
    expect(answer.body).toContain('shell')
  })

  it('leaves a method the fallback owns to the fallback', async () => {
    harness = await launch({ withShell: true })
    // The stand-in fallback answers every method; the point is that the gate did
    // not turn a non-navigation into a redirect.
    const answer = await harness.call({ path: '/', host: DECLARED_AUTHORITY, method: 'POST', body: '{}' })
    expect(answer.status).toBe(200)
  })

  it('leaves the shell ungated when no provider is mounted', async () => {
    harness = await launch({ withAuth: false, withShell: true })
    const answer = await harness.call({ path: '/', host: DECLARED_AUTHORITY })
    expect(answer.status).toBe(200)
    expect(answer.body).toContain('shell')
  })
})

/**
 * The browser sign-in surface: the login page and the sign-in, sign-out, and
 * status endpoints.
 *
 * These routes live with the `/api` carrier because they answer the same
 * question about the same browser, and because the authority fence they sit
 * behind has exactly one home here. They are gated by that fence but NOT by the
 * authentication requirement — an unauthenticated caller must be able to reach
 * sign-in — so `Host` still has to name an authority this deployment serves,
 * which keeps a DNS-rebound page from using the endpoint as a password oracle.
 *
 * Every mutating endpoint requires an `application/json` body, for the reason
 * the `/api` media-type fence exists: a cross-site "simple" POST cannot declare
 * that type, so it is forced into a preflight this server never answers.
 * @module @deepseek-ai/dsh-client-connection/auth-routes
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import {
  LOGIN_PAGE_HTML,
  LOGIN_PATH,
  SIGN_IN_PATH,
  SIGN_OUT_PATH,
  STATUS_PATH,
  type WebAuth,
} from '@deepseek-ai/dsh-host-web-auth'
import { isTrustedApiRequest } from './api-request-trust.ts'

/**
 * Body cap for the sign-in endpoint. A submitted secret is tens of bytes; the
 * cap exists so an unauthenticated caller cannot make the host buffer more.
 */
const MAX_SIGN_IN_BODY_BYTES = 4096

/** Headers every auth response carries: never cached, never sniffed. */
const NO_STORE = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } as const

/**
 * Content Security Policy for the login page: it needs its own inline style and
 * script and nothing else, so every other source is denied outright.
 */
const LOGIN_PAGE_CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  "script-src 'unsafe-inline'",
  "connect-src 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ')

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body)
  res.writeHead(status, { ...NO_STORE, 'content-type': 'application/json', ...headers })
  res.end(payload)
}

/** Why a body could not be read, and whether the connection must be closed after answering. */
interface BodyFailure {
  status: number
  message: string
  closeConnection?: boolean
}

/**
 * Read a bounded JSON request body.
 * @param req - the incoming request.
 * @returns the parsed body, or a failure status to answer with.
 */
async function readJsonBody(req: IncomingMessage): Promise<{ body: unknown } | BodyFailure> {
  const mediaType = req.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase()
  if (mediaType !== 'application/json') {
    return { status: 415, message: 'Content type must be application/json.' }
  }
  const chunks: Buffer[] = []
  let received = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    received += buffer.byteLength
    if (received > MAX_SIGN_IN_BODY_BYTES) {
      // Stop consuming and let the caller answer; the response carries
      // `Connection: close`, so the socket is torn down after it flushes.
      // Destroying the request here would kill the response with it.
      return { status: 413, message: 'Request body is too large.', closeConnection: true }
    }
    chunks.push(buffer)
  }
  try {
    return { body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }
  } catch {
    return { status: 400, message: 'Request body is not JSON.' }
  }
}

/** Answer one sign-in attempt. */
async function handleSignIn(webAuth: WebAuth, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const parsed = await readJsonBody(req)
  if (!('body' in parsed)) {
    sendJson(res, parsed.status, { message: parsed.message },
      parsed.closeConnection === true ? { connection: 'close' } : {})
    return
  }
  const secret = (parsed.body as { secret?: unknown } | null)?.secret
  if (typeof secret !== 'string') {
    sendJson(res, 400, { message: 'Request body must carry a string "secret".' })
    return
  }
  const result = await webAuth.signIn(secret, { ...req.socket.remoteAddress !== undefined && { address: req.socket.remoteAddress } }, req)
  if (result.outcome === 'verified') {
    sendJson(res, 200, { ok: true }, { 'set-cookie': result.setCookie })
    return
  }
  if (result.outcome === 'locked') {
    sendJson(res, 429, {
      message: `Too many failed attempts. Try again in ${String(result.retryAfterSeconds)}s.`,
    }, { 'retry-after': String(result.retryAfterSeconds) })
    return
  }
  if (result.outcome === 'unsupported') {
    sendJson(res, 400, { message: 'This harness accepts no submitted secret; access is granted by its proxy.' })
    return
  }
  // Deliberately identical for a wrong secret and an unknown one: the endpoint
  // reports nothing a caller could use to enumerate what it accepts.
  sendJson(res, 401, { message: 'Incorrect password.' })
}

/**
 * Mount the sign-in surface behind the browser-authority fence.
 * @param ctx - the Connection plugin context, carrying `webServer`.
 * @param webAuth - the mounted authentication seam.
 * @param trustedHosts - non-loopback authorities this deployment serves.
 */
export function registerAuthRoutes(ctx: Context, webAuth: WebAuth, trustedHosts: readonly string[]): void {
  const gated = (
    method: 'GET' | 'POST',
    handle: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>,
  ): WebRoute['handler'] => async (req, res) => {
    if (!isTrustedApiRequest(req, trustedHosts)) {
      res.writeHead(403, NO_STORE)
      res.end('forbidden')
      return
    }
    if (req.method !== method) {
      res.writeHead(405, { ...NO_STORE, allow: method })
      res.end()
      return
    }
    await handle(req, res)
  }

  const routes: WebRoute[] = [
    {
      kind: 'exact',
      path: LOGIN_PATH,
      handler: gated('GET', (_req, res) => {
        res.writeHead(200, {
          ...NO_STORE,
          'content-type': 'text/html; charset=utf-8',
          'content-security-policy': LOGIN_PAGE_CSP,
        })
        res.end(LOGIN_PAGE_HTML)
      }),
    },
    {
      kind: 'exact',
      path: SIGN_IN_PATH,
      handler: gated('POST', (req, res) => handleSignIn(webAuth, req, res)),
    },
    {
      kind: 'exact',
      path: SIGN_OUT_PATH,
      handler: gated('POST', (req, res) => {
        sendJson(res, 200, { ok: true }, { 'set-cookie': webAuth.signOut(req).setCookie })
      }),
    },
    {
      kind: 'exact',
      path: STATUS_PATH,
      handler: gated('GET', async (req, res) => { sendJson(res, 200, await webAuth.status(req)) }),
    },
  ]
  for (const route of routes) {
    ctx.effect(() => ctx.webServer.register(route), `client-connection: ${route.path} route`)
  }

  // The app shell is static and the fallback would hand it to anyone who reaches
  // the port. Every `/api` call it makes is still refused, so nothing leaks — but
  // an anonymous browser renders the harness's empty state instead of being told
  // to sign in, which reads as "no authentication" to the person looking at it.
  // Send that navigation to the page that can fix it.
  ctx.effect(() => ctx.webServer.registerFallbackGuard(async (req, res) => {
    // Not a composition that authenticates anyone: leave the shell alone.
    if (!webAuth.required) return false
    // The fallback answers 405 for anything but GET/HEAD; that stays its call.
    if (req.method !== 'GET' && req.method !== 'HEAD') return false
    // Loopback reaches everything without a credential, the shell included.
    if (isTrustedApiRequest(req, [])) return false
    if (await webAuth.authenticate(req) !== undefined) return false
    res.writeHead(302, { ...NO_STORE, location: LOGIN_PATH })
    res.end()
    return true
  }), 'client-connection: unauthenticated shell gate')
}

/**
 * URL paths the web-authentication seam serves. They sit under one prefix so a
 * deployment fronting the harness can reason about the sign-in surface as a
 * single route group, and so the `/api` fence's paths never overlap them.
 * @module @deepseek-ai/dsh-host-web-auth/paths
 */

/** Prefix owning every route this seam registers. */
export const AUTH_PATH = '/auth'

/** Sign-in page: the HTML document a browser is sent to. */
export const LOGIN_PATH = `${AUTH_PATH}/login`

/** Sign-in endpoint: `POST` a JSON `{ secret }`; answers `Set-Cookie` on success. */
export const SIGN_IN_PATH = `${AUTH_PATH}/sign-in`

/** Sign-out endpoint: `POST` revokes the presented session and clears the cookie. */
export const SIGN_OUT_PATH = `${AUTH_PATH}/sign-out`

/** Status endpoint: `GET` reports whether authentication is required and satisfied. */
export const STATUS_PATH = `${AUTH_PATH}/status`

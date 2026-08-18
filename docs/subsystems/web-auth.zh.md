# Web 认证

[English](web-auth.md) | 中文

[dsh-host-web-auth](../../packages/host/web-auth) 是决定谁可以访问 GUI Host 面向浏览器一侧的能力 seam。它提供 `ctx.webAuth`：提供方注册表、登录会话生命周期，以及共享的会话 Cookie 编码。它不属于 Agent 循环，也不注册任何路由——该 seam 只回答关于某个请求的问题，由持有浏览器权威栅栏的载体来应用这个答案。

源码：[`packages/host/web-auth/src/index.ts`](../../packages/host/web-auth/src/index.ts)

## 这个 seam 为何存在，以及它不是什么

`dsh web` 默认绑定回环地址，每个 `/api` 请求都要通过一道浏览器信任栅栏，要求 `Host` 是回环地址或已声明的 `trustedHosts` 权威。该栅栏是 DNS 重绑定与跨站防御，并且[有意不是认证](../../.agents/notes/implemented/architecture/2026-07-28-api-browser-trust-boundary.md)：在绑定全部网卡时，CLI 会把本机的局域网 IP 字面量派生进 `trustedHosts`，以便它对外公布的局域网 URL 可用，这意味着该网络上的任何客户端都能触达 `session.prompt`——一个会执行 bash 的 Agent。这个 seam 在产品内部补上了缺失的那一层，因此部署既不必给已发布的产物打补丁，也不必在 Harness 前面架一个外部网关。

可达性仍然由 webserver 的绑定策略决定，栅栏认可哪些权威仍然由 connection 行决定。认证叠加在两者之上：它增加一项要求，且绝不放宽 `Host` 检查。

## 身份与两种校验面

```ts type-equiv
/** A principal one provider has verified for the current request. */
interface WebAuthIdentity {
  /** Registry id of the provider that verified this principal. */
  readonly provider: string
  /**
   * Label naming who was verified, for the sign-in session record and
   * diagnostics. Providers that authenticate a deployment secret rather than a
   * person use a fixed label; the seam never parses it.
   */
  readonly subject: string
}
```

```ts type-equiv
/**
 * The request facts a provider may read. Both HTTP representations the host
 * serves are accepted, matching the trust fence's own request type: the
 * `node:http` route handlers and the Fetch handlers the `/api` bridge builds.
 */
interface WebAuthRequest {
  readonly headers: IncomingHttpHeaders | Headers
}
```

```ts type-equiv
/** Where a sign-in attempt came from, for provider-owned rate limiting. */
interface WebAuthClient {
  /**
   * Remote peer address of the submitting socket, or undefined when the
   * carrier could not report one. Behind a reverse proxy every attempt shares
   * the proxy's address, so a provider keying a lockout on this value limits
   * the proxy as one client.
   */
  readonly address?: string
}
```

提供方至少要提供一种校验面，两种都不提供的提供方会被该 seam 拒绝：这样的提供方永远无法认证任何请求，却又会让认证成为必需，从而把部署方锁在自己的 Harness 之外。

```ts type-equiv
/**
 * One authentication mechanism. A provider supplies at least one verification
 * surface; the seam asserts that at registration, because a provider with
 * neither could never authenticate anything and would silently weaken a
 * deployment that believed it had mounted authentication.
 */
interface WebAuthProvider {
  /** Registry key; duplicates are refused. */
  readonly id: string
  /**
   * Verify a credential this request carries on its own — a tunnel's signed
   * assertion header, for example. Called on every request the fence gates, so
   * implementations must be cheap and must not block on the network per call.
   * @param request - the request's headers.
   * @returns the verified principal, or undefined when the request carries no
   * credential this provider owns or the credential does not verify.
   */
  verifyRequest?(request: WebAuthRequest): Promise<WebAuthIdentity | undefined>
  /**
   * Verify a secret submitted to the seam's sign-in endpoint. Providers
   * implementing this get a browser sign-in session cookie on success.
   * @param secret - the submitted secret, verbatim.
   * @param client - where the attempt came from, for rate limiting.
   * @returns whether the secret verified, was wrong, or is currently locked out.
   */
  verifySecret?(secret: string, client: WebAuthClient): Promise<WebAuthSignInOutcome>
}
```

```ts type-equiv
/** Outcome of verifying a secret submitted through the seam's sign-in endpoint. */
type WebAuthSignInOutcome =
  /** The secret is this provider's and correct. */
  | { readonly outcome: 'verified'; readonly identity: WebAuthIdentity }
  /** The secret is this provider's and wrong. */
  | { readonly outcome: 'rejected' }
  /**
   * This provider refuses to judge further attempts from this client for now.
   * The seam reports the wait to the caller and never falls through to another
   * provider, so one provider's lockout cannot be side-stepped.
   */
  | { readonly outcome: 'locked'; readonly retryAfterSeconds: number }
```

校验顺序不依赖注册顺序：先用一次 map 查找认可已存在的登录会话，然后依次运行各个请求凭据提供方，直到其中一个校验通过。只有请求凭据提供方参与这一步，因此新增一个交互式提供方不会增加任何单请求开销。

## 登录结果

```ts type-equiv
/** What a caller may learn about the authentication state without being signed in. */
interface WebAuthStatus {
  /** Whether non-loopback access requires authentication in this composition. */
  readonly required: boolean
  /** Whether THIS request already carries a verified principal. */
  readonly authenticated: boolean
  /** Whether a mounted provider accepts a submitted secret, i.e. whether the sign-in page can work. */
  readonly interactive: boolean
}
```

```ts type-equiv
/** Result of a sign-in attempt. */
type SignInResult =
  | {
    readonly outcome: 'verified'
    readonly identity: WebAuthIdentity
    /** `Set-Cookie` value establishing the browser session. */
    readonly setCookie: string
  }
  | SignInFailure
```

## 会话与 Cookie

会话以 256 位随机令牌的 SHA-256 摘要形式存放在进程内存中，因此内存泄露不会产生可用的 Cookie，登出也是真正吊销，而不是等一个自描述令牌过期。它们有意不做持久化：重启 Harness 会使每个浏览器会话失效，这是不在磁盘上保存签名密钥所换来的代价。活跃记录数有上限，优先淘汰已过期的记录，其次淘汰最旧的，因此最新的会话得以保留。

每个签发的 Cookie 都带有 `HttpOnly`、`SameSite=Strict`、`Path=/`，以及与服务端记录一致的 `Max-Age`。`SameSite=Strict` 正是让已认证请求可以被安全放行的原因：跨站上下文——包括被 DNS 重绑定的页面，它与 Cookie 签发时对应的权威属于不同站点——永远不会携带该 Cookie，因此持有它证明的是第一方上下文，而不仅仅是一个可达的套接字。是否设置 `Secure` 属于部署事实而非进程可以自行观察的信息，因为即使浏览器是通过隧道以 HTTPS 访问，Harness 本身仍以纯 HTTP 提供服务；`cookieSecure` 可选 `auto`（当请求报告存在 HTTPS 转发跳时设置）、`always` 或 `never`。

## 载体如何应用这个答案

[dsh-client-connection](../../packages/client/connection) 是消费方。它按请求读取这个可选的 seam，把登录界面挂在自己的权威栅栏之后，并在 [`api-request-gate.ts`](../../packages/client/connection/src/api-request-gate.ts) 中合并两个判断：

- 普通 `/api` 请求必须通过权威栅栏；一旦挂载了提供方，还必须来自回环地址或携带已校验的主体。
- `loopback` 权威的请求——配置面、原生对话框，以及那些因为 `trustedHosts` 不是认证而被钉死的方法——可以来自回环地址，或者来自已声明权威且携带已校验主体。这个钉死等待的正是这一条件。
- 回环地址无需凭据仍可访问一切。回环访问本身就意味着能以本进程身份执行代码，因此对它要求密码保护不了任何东西，却会破坏健康检查与本地工具链。
- 在任一权威下，凭据都不能替代 `Host` 检查。

未挂载任何提供方的组合在上述每一种情形下都不受影响：这项要求跟随提供方，而不是跟随该 seam 所在的行。

登录界面由 `/auth` 下的四条路由组成——登录页、登录、登出与状态。它们位于权威栅栏之后，使被重绑定的页面无法把登录端点当作密码判定器使用；其中会产生副作用的路由要求 `application/json` 请求体，从而把任何跨站尝试逼入本服务器从不应答的预检。静态资源不在门控范围内：这项要求覆盖 `/api`，与栅栏自身的范围一致。

## 提供方

| 包 | 校验对象 |
|---|---|
| [dsh-host-web-auth-password](../../packages/host/web-auth-password) | 提交的密码；首次启动时生成，以 scrypt 校验值存储，并按客户端做失败锁定 |
| [dsh-host-web-auth-cloudflare-access](../../packages/host/web-auth-cloudflare-access) | Cloudflare Access 转发的 RS256 应用令牌，针对团队轮换的密钥集校验 |

由于传输层与身份证明彼此正交，部署方可以只更换其中一侧：前面用 Cloudflare Tunnel、Tailscale 或局域网反向代理，后面配任意合适的提供方行。

<!-- BEGIN GENERATED cordis-surface (gen-cordis-catalog.ts) — do not edit between markers -->

<a id="cordis-surface"></a>

## Cordis API

Generated from source by `scripts/gen-cordis-catalog.ts` (verified fresh by `pnpm run verify-cordis-catalog` in doc-sync; regenerate with `pnpm run gen-cordis-catalog`) — this section is byte-identical in both language sides of the page. Signature blocks use a `ts cordis-catalog` fence and keep the original source JSDoc; dispatch modes are defined in the [primer](../cordis-primer.md#dispatch-modes), and the framework-inherited `ctx` API lives in [cordis-api/inherited.md](../cordis-api/inherited.md).

<a id="ctxwebauth--webauth"></a>

### `ctx.webAuth` — `WebAuth`

The authentication service. Providers register into it; the browser-transport Consumer reads it to decide whether a request may pass the `/api` fence.

Verification order is deliberate and not registration-dependent: an existing sign-in session is honored first (one map lookup, no provider work), then each provider's per-request credential check runs until one verifies. Only request-credential providers participate there, so adding an interactive provider never adds per-request cost.

```ts cordis-catalog
/**
 * Register one authentication provider. Disposed with the calling fiber.
 * @param provider - the mechanism; its `id` is the registry key.
 * @returns the disposer that unregisters it.
 * @throws when the id is already registered, or when the provider supplies
 * neither verification surface — such a provider could never authenticate
 * anything while still making authentication REQUIRED, locking the
 * deployment out of its own harness.
 */
register(provider: WebAuthProvider): () => void

/**
 * Resolve the verified principal behind one request.
 * @param request - the request's headers.
 * @returns the principal, or undefined when the request carries none.
 */
async authenticate(request: WebAuthRequest): Promise<WebAuthIdentity | undefined>

/**
 * Report the authentication state for one request.
 * @param request - the request's headers.
 * @returns what the caller may know before signing in.
 */
async status(request: WebAuthRequest): Promise<WebAuthStatus>

/**
 * Verify a submitted secret and, on success, mint a browser session.
 *
 * A provider reporting a lockout ends the attempt immediately rather than
 * letting the secret fall through to the next provider, so a second mounted
 * provider can never be used to side-step the first one's rate limit.
 * @param secret - the submitted secret, verbatim.
 * @param client - where the attempt came from, for provider rate limiting.
 * @param request - the request's headers, read for the cookie's `Secure` decision.
 * @returns the minted session, or why no session was minted.
 */
async signIn(secret: string, client: WebAuthClient, request: WebAuthRequest): Promise<SignInResult>

/**
 * Revoke the sign-in session a request presents.
 * @param request - the request's headers.
 * @returns the `Set-Cookie` value clearing the browser's cookie. Emitted even
 * when no live session matched, so a stale cookie is always cleared.
 */
signOut(request: WebAuthRequest): { setCookie: string }
```

Source: [`packages/host/web-auth/src/index.ts:119`](../../packages/host/web-auth/src/index.ts)
<!-- END GENERATED cordis-surface -->

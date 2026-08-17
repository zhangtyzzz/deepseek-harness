# `@deepseek-ai/dsh-host-web-auth`

[English](README.md) | 中文

Web 访问认证能力缝（`ctx.webAuth`）的 Service Definition：提供方注册表、浏览器登录会话生命周期，以及决定会话 Cookie 安全属性的唯一位置。挂载它并至少配置一个提供方，即可要求远程访问 Web GUI 时进行认证；未挂载任何提供方的组合与此前完全一致。

该缝只回答一个问题——这个请求是否携带已校验的主体？——并签发或吊销记录该主体的浏览器会话。它不注册路由，也不读取 `Host`：持有浏览器权威围栏的消费方 [`dsh-client-connection`](../../client/connection/README.md) 把登录界面挂在该围栏之后，并在 `/api` 上强制这项要求。这样，部署认可哪些权威始终是单一位置上的单一事实，也让本包与它所保护的传输层相互独立。

## 为何需要它

`dsh web` 默认绑定回环地址，`/api` 围栏信任一份 `Host` 允许列表。该围栏是 DNS 重绑定与跨站防御，[按设计不是认证层](../../../.agents/notes/implemented/architecture/2026-07-28-api-browser-trust-boundary.md)：在绑定全部网卡时，CLI 会把本机局域网字面量派生进 `trustedHosts`，于是局域网上的任何客户端都能触达 `session.prompt`——一个会执行 bash 的 Agent。给远程访问加上认证需要的是产品内的能力，而不是打补丁的产物或外挂网关；而且它必须可替换，因为部署所用的传输方式（Cloudflare Tunnel、Tailscale、局域网反向代理）与它如何证明身份是彼此正交的。

## Service API

| 成员 | 用途 |
|---|---|
| `register(provider)` | 注册一种机制；返回 disposer，作用域为调用方 fiber。拒绝重复 id，也拒绝两种校验面都不提供的提供方。 |
| `required` | 是否已挂载任何提供方，即是否需要认证。 |
| `interactive` | 已挂载的提供方是否接受提交的密钥，即登录页是否可用。 |
| `authenticate(request)` | 该请求背后已校验的主体，或 `undefined`。 |
| `status(request)` | 供登录页使用的 `{ required, authenticated, interactive }`。 |
| `signIn(secret, client, request)` | 校验提交的密钥并签发会话；返回 `Set-Cookie` 值，或未签发会话的原因。 |
| `signOut(request)` | 吊销请求出示的会话；返回清除浏览器 Cookie 的 `Set-Cookie` 值。 |

## 提供方角色

提供方需提供一种或两种校验面，两种都不提供的会被拒绝——这样的提供方永远无法认证任何请求，却又会让认证成为必需，从而把部署方锁在自己的 Harness 之外。

- **`verifyRequest(request)`** —— 请求自身携带的凭据，例如隧道的签名断言头。每个受门控的请求都会调用它，因此必须开销很小，且不得按请求阻塞在网络上。[`web-auth-cloudflare-access`](../web-auth-cloudflare-access/README.md) 属于此类。
- **`verifySecret(secret, client)`** —— 提交到登录端点的密钥；成功后获得浏览器会话 Cookie。[`web-auth-password`](../web-auth-password/README.md) 属于此类。其判定区分 `rejected` 与 `locked`，且 `locked` 会终止本次尝试而不会落到下一个提供方，因此第二个已挂载的提供方绝不能被用来绕过第一个的限流。

校验顺序不依赖注册顺序：先用一次 map 查找认可已存在的登录会话，然后依次运行各个请求凭据提供方，直到其中一个校验通过。

## 会话记录与 Cookie

会话以高熵令牌的 SHA-256 摘要形式存放在进程内存中，因此内存泄露不会产生可用的 Cookie，登出也是真正吊销。它们有意不做持久化：重启 Harness 会使每个浏览器会话失效，这是不在磁盘上保存签名密钥所换来的代价。活跃记录数有上限，优先淘汰最旧的记录。

每个签发的 Cookie 都带有 `HttpOnly`、`SameSite=Strict`、`Path=/`，以及与服务端记录一致的 `Max-Age`。`SameSite=Strict` 正是让已认证请求可以安全通过权威围栏的原因：跨站上下文——包括被 DNS 重绑定的页面，它与 Cookie 签发时对应的权威属于不同站点——永远不会携带该 Cookie，因此持有它证明的是第一方上下文，而不仅仅是一个可达的套接字。

`Secure` 属于部署事实而非进程可自行观察的信息：即使浏览器通过隧道以 HTTPS 访问，Harness 仍以纯 HTTP 提供服务。`cookieSecure: auto` 在请求报告存在 HTTPS 转发跳时设置该属性，`always` 适用于只能通过 HTTPS 访问的部署，`never` 则是纯 HTTP 局域网服务所必需的。`auto` 仅信任 `x-forwarded-proto` 来「增加」该属性，因此剥掉该头的客户端只会削弱自己的 Cookie。

## 配置

| 键 | 默认值 | 含义 |
|---|---|---|
| `sessionTtlSeconds` | `43200`（12 小时） | 浏览器会话有效期；服务端记录在同一时刻过期。 |
| `cookieSecure` | `auto` | 签发的 Cookie 是否标记 `Secure`。 |

## 如何启用

该缝不随任何 profile 发布：挂载它本身就是开启认证的动作，因此默认的 `web` profile 不受影响。部署方通过官方的补丁层加入这些行——`dsh --profile web --patch <文件>`——并且由于可达性与受信权威仍归各自的配置所有，会在同一份 overlay 中一并设置：

```yaml
# Listen beyond loopback; publish this port only where the tunnel or proxy reaches it.
- id: webserver
  config:
    host: 0.0.0.0
    port: 3080

# The authority the browser addresses. Required with or without authentication:
# the fence is a DNS-rebinding defense and authentication never replaces it.
- id: connection
  config:
    trustedHosts: ['dsh.example.com']

- insert:
    - id: web-auth
      name: '@deepseek-ai/dsh-host-web-auth'
      config:
        cookieSecure: always

    - id: web-auth-password
      name: '@deepseek-ai/dsh-host-web-auth-password'
      config:
        file: !!js dshHomePath('web-auth', 'password.json')
```

首次启动会打印生成的密码一次。更换机制就是更换最后那一行——例如 Cloudflare Access 部署改用 `@deepseek-ai/dsh-host-web-auth-cloudflare-access`，并给出 `teamDomain` 与 `audience`——同时挂载两行也是合法的：隧道令牌自动完成认证，而密码在局域网上仍然可用。

## Model Experience

None, as the authentication seam decides who may reach the carrier and registers nothing model-facing.

#### KV Cache effect

None; this package neither assembles nor sends a provider request.

## Known Limitations and Deferred Work

- **登录会话无法跨重启存活** —— 记录仅存在于进程内，因此 Harness 重启后每个浏览器都要重新认证。要持久化就必须在磁盘上保存签名密钥或会话表，这超出了本缝所决定的范围。
- **静态资源不在门控范围内** —— 这项要求覆盖 `/api` 与登录界面，与围栏自身的范围一致。未认证的浏览器仍会下载 shell bundle（与 npm 提供的公开产物相同），只有在调用 API 时才会失败；它不会被重定向到登录页。对 SPA 做门控需要占用 webserver 唯一的 fallback 席位，而该席位由 [`frontend-static`](../frontend-static/README.md) 持有。
- **没有应用内登出或会话界面** —— `signOut` 可通过 HTTP 访问，但没有浏览器插件暴露它，因此提前结束会话意味着清除 Cookie 或重启 Harness。

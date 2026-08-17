# `@deepseek-ai/dsh-host-web-auth-cloudflare-access`

[English](README.md) | 中文

[Web 访问认证能力缝](../web-auth/README.md)的 Cloudflare Access 提供方。它校验 Cloudflare Access 在每个被代理请求上转发的签名应用令牌，并报告已认证的用户。

## 为何校验不可省略

Cloudflare Access 在边缘终结用户会话，并在 `Cf-Access-Jwt-Assertion` 中转发一个 JWT（浏览器导航则使用 `CF_Authorization` Cookie）。在此处校验该令牌的签名与受众，正是让隧道的判断对 Harness 可信的原因：否则，任何直接触达源站的调用方——绕过隧道，而暴露的容器端口恰好允许这样做——只需自行附上该头即可。

`alg` 被钉死为 RS256，而不是从令牌中读取。信任令牌自身的头部是经典的 JWT 破解手法：`none` 会完全跳过校验，而 HMAC 类算法会让调用方能用公钥当作共享密钥来签名。只有同时满足以下条件的令牌才被接受：签名可用团队当前密钥集验证通过、`iss` 等于团队域源、`aud` 包含所配置的应用标签（这可阻止同团队内为其他应用签发的令牌触达本 Harness）、且有效期窗口在一分钟时钟偏差内成立。身份 subject 取令牌的 `email`，缺失时回退到 `sub`。

格式错误、伪造或已过期的令牌会通过 logger 上报，并按普通的未认证请求处理。密钥集拉取失败同样如此处理，而不是让请求失败，因此边缘故障无法被转化为 500 判定器。

## 签名密钥

Cloudflare 会轮换签名密钥，因此密钥是拉取而非配置的。成功获取的密钥集会服务一小时后再做计划刷新；命名了未知密钥 id 的令牌在每个冷却窗口内最多触发一次重新拉取——否则一串伪造的密钥 id 就会变成无界的出站请求。并发调用方共享同一次进行中的拉取，且刷新会整体替换密钥集，因此 Cloudflare 撤下的密钥会立即停止校验令牌。

## 配置

| 键 | 默认值 | 含义 |
|---|---|---|
| `teamDomain` | 必填 | Access 团队域，例如 `example.cloudflareaccess.com`。必须是裸主机名；否则在加载时失败，而不是生成一个任何令牌都无法匹配的 issuer。期望的 `iss` 为该域的 `https://` 源。 |
| `audience` | 必填 | Access 应用的 Audience（AUD）标签。 |
| `certsUrl` | `https://<teamDomain>/cdn-cgi/access/certs` | 签名密钥集端点，供使用自定义 Access 主机名的部署使用。 |

## 部署说明

本提供方负责认证，而不负责让 Harness 可达。webserver 行仍决定绑定地址，connection 行仍声明围栏认可的权威——无论是否挂载提供方，位于 `dsh.example.com` 的隧道部署都需要把该名字写入 `trustedHosts`。

## Model Experience

None, as the Cloudflare Access provider verifies a forwarded token for the authentication seam and registers nothing model-facing.

#### KV Cache effect

None; this package neither assembles nor sends a provider request.

## Known Limitations and Deferred Work

- **不支持按群组或邮箱做授权** —— 任何对所配置应用有效的令牌都会被接受，因此访问控制完全留在 Access 策略中。按 claim 过滤会重复 Cloudflare 已经承担的判断，但把一个应用共享给多个希望彼此隔离的受众的部署无法在此表达这种区分。
- **仅支持 RS256** —— 即 Cloudflare Access 所签发的算法。配置为其他签名算法的团队会被拒绝，而不是协商。
- **密钥集不做预加载** —— 挂载后的第一个请求要承担密钥集拉取开销，且其五秒超时是固定上界而非可配置项。

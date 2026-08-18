# dsh Web 界面的容器镜像

[English](README.md) | 中文

在容器里运行 `dsh web`，可从宿主机之外访问，而要求远端调用方证明身份的是 Harness 自己。这里不给任何
已安装文件打补丁，也不在 Harness 前面架任何东西：可达性来自官方 patch 层，准入来自产品内的
`ctx.webAuth` seam。

## 为何从源码构建

可插拔 Web 认证能力在 `master` 上，但尚未进入任何已发布的 `@deepseek-ai/dsh` 版本，因此镜像构建整个
工作区，而不是安装 npm 产物。

## 直接拉取而不构建

`.github/workflows/docker-image.yml` 会在每次推送到 `master` 时发布多平台镜像——`linux/amd64` 与
`linux/arm64`，各自在原生 runner 上构建——推到 `ghcr.io/<仓库所有者>/dsh-web`。对这个 fork 来说就是
`ghcr.io/zhangtyzzz/dsh-web`：

```bash
docker pull ghcr.io/zhangtyzzz/dsh-web:latest
```

Pull request 会构建两个平台但不发布，因此让镜像构建失败的改动会在标签移动之前被发现。

## 构建与运行

```bash
# from the repository root
docker build -f docker/Dockerfile -t dsh-web:local .

# loopback only — nothing outside the host can reach it
docker run --rm -p 127.0.0.1:3080:3080 -v dsh-home:/dsh-home dsh-web:local

# reachable as https://dsh.example.com through a tunnel or reverse proxy
docker run -d --name dsh \
  -p 3080:3080 \
  -e DSH_TRUSTED_HOST=dsh.example.com \
  -e DSH_COOKIE_SECURE=always \
  -v dsh-home:/dsh-home \
  -v "$PWD/workspace:/workspace" \
  dsh-web:local
```

或者用 compose，在本目录下执行：`docker compose up -d --build`。

**密码只在首次启动时打印一次。** 从容器日志里读取（`docker logs dsh`）——持久化的只有它的 scrypt
verifier，位于 `/dsh-home/web-auth/password.json`。删除该文件会在下次启动时轮换密码。

## 环境变量

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `DSH_TRUSTED_HOST` | *（空）* | `/api` 信任栅栏接受的权威，逗号分隔，例如 `dsh.example.com,192.168.1.10:3080`。留空意味着只对回环有效，无论端口怎么映射。 |
| `DSH_PORT` | `3080` | 容器内的端口。 |
| `DSH_BIND` | `0.0.0.0` | 容器内的绑定地址。通过 patch 层设置，因为 `dsh web --host 0.0.0.0` 被 CLI 有意拒绝。 |
| `DSH_COOKIE_SECURE` | `auto` | `auto` 在请求报告了 HTTPS 转发跳时给会话 Cookie 标记 `Secure`；`always` 适用于全程 HTTPS 的部署；`never` 用于纯 HTTP 的局域网。 |
| `DSH_SESSION_TTL_SECONDS` | `43200` | 登录会话的存活时长。 |
| `DSH_WEB_AUTH_PASSWORD` | `1` | 是否挂载本地密码提供方。置 `0` 则只剩外部身份这一条进入路径。 |
| `DSH_AUTH_MAX_ATTEMPTS` | `5` | 同一客户端连续失败多少次后锁定。 |
| `DSH_AUTH_LOCKOUT_SECONDS` | `300` | 一次锁定拒绝该客户端多久。 |
| `DSH_CF_ACCESS_TEAM` | *（空）* | Cloudflare Access 的团队域名，写成裸主机名，例如 `example.cloudflareaccess.com`。设置它即挂载 Access 提供方，必须与 audience 同时设置。 |
| `DSH_CF_ACCESS_AUD` | *（空）* | Access 应用的 Audience（AUD）标签。只有 `aud` 含该值的 token 才被接受。 |
| `DSH_CF_ACCESS_CERTS_URL` | *（团队域名默认路径）* | 签名密钥集端点，供部署在自定义 Access 主机名上的情形使用。 |
| `DSH_PRINT_CONFIG` | `0` | 置 `1` 时在启动阶段把渲染出的 patch overlay 打到 stderr。 |
| `DSH_HOME` | `/dsh-home` | Harness 状态：会话、设置、凭据、密码 verifier。 |

## 用 Cloudflare Access 挡在前面

设置 `DSH_CF_ACCESS_TEAM` 与 `DSH_CF_ACCESS_AUD` 即挂载 Access 提供方，于是携带有效 Access token 的
请求无需密码提示即为已认证。token 在这里被校验——RS256 且 `alg` 钉死、`iss` 等于团队域名的 origin、
`aud` 必须含配置的标签——因此绕过隧道直连 origin 的调用方无法仅凭断言那个头进来。

除非你另有进入路径，否则请把密码提供方一并挂着：Access 的密钥集要经网络获取，那里出故障会让携带
头部凭据的调用方降级为未认证。

当 `DSH_TRUSTED_HOST` 指定了权威而一个提供方都没启用时，entrypoint 会拒绝启动——那种组合等于按认证
出现之前的方式对外提供该权威。

## entrypoint 渲染出什么

`$DSH_HOME/docker.cordis.yml`，每次启动重新生成并作为 `--patch` 传入：一个绑定
`${DSH_BIND}:${DSH_PORT}` 的 `webserver` 行、一个携带 `trustedHosts` 的 `connection` 行，以及两个
挂载 `@deepseek-ai/dsh-host-web-auth` 与 `@deepseek-ai/dsh-host-web-auth-password` 的 insert 行。

## 对外暴露之前值得知道的事

- **远程访问时 `DSH_TRUSTED_HOST` 不是可选项。** `Host` 既不是回环地址也不是已声明权威的请求，即便
  带着有效的会话 Cookie 也会被拒绝——那是 DNS 重绑定防御，认证叠加在它之上而非取代它。
- **已认证的远程操作者能触达配置面**，包括 `credentials.set` 与那些设置类方法；对匿名调用方而言它们
  被钉在回环上。这是登录之后的既定后果。
- **重启容器会让所有浏览器登出。** 会话按设计是进程内的；磁盘上不写任何签名密钥。
- **挂载卷必须对 uid 1000 可写。** Agent 会执行任意代码，所以容器不以 root 运行；`DSH_HOME` 不可写时
  entrypoint 会明确报错退出。
- 镜像自带 Harness 自己的工具面（`bash`、`git`、`ripgrep`）。任何登录进来的人都能以 uid 1000 在容器里
  执行命令。

## 这里没有做的事

- 只挂载了密码提供方。Cloudflare Access 提供方就在同一个 seam 里，加上它意味着多一个 insert 行加一个
  `cloudflared` 边车。
- 镜像装的是构建后的整棵工作区，因此体积很大。瘦身意味着让 `pnpm deploy` 产出一棵可运行的树——今天
  它做不到。
- 如果这套东西要进上游，本页面向用户的那一半应当放到 `docs/` 下并配 `.zh.md`，届时文档门禁会强制这一点。

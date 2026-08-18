# `@deepseek-ai/dsh-host-web-auth-password`

[English](README.md) | 中文

[Web 访问认证能力缝](../web-auth/README.md)的本地密码提供方。它在首次启动时生成密码，只保存该密码的 scrypt 校验值，并按客户端对连续失败做限流。

## 首次启动与轮换

不存在默认、内置或写在文档里的密码：首次启动时提供方从 32 符号字母表中生成 25 个符号——125 位熵——并打印一次，因为持久化的只有 scrypt 校验值，之后无法再恢复该密码。字母表不含 `I`、`L`、`O`、`U`，这既消除了从终端读取密码时的转写歧义，也让数字 `0` 与 `1` 不再有歧义。

凭据文件通过独占创建、以仅所有者可读的权限生成，因此两个进程同时首启一个全新的 Harness 主目录时会收敛到同一份凭据，而不会互相静默覆盖；竞争失败的一方会读取胜者的文件，而不会作废它已经打印过的密码。删除该文件会在下次启动时轮换密码。读取时会校验其 `version`，不匹配则大声失败——本仓库拒绝旧的磁盘格式，而不做迁移。

## 锁定

存储的密码带有 125 位熵，因此一旦尝试被限流，猜解就不可行；锁定正是使暴露密码端点成为可行做法的前提。同一客户端连续失败达到 `maxAttempts` 次后，提供方在 `lockoutSeconds` 内报告 `locked`，该缝将其呈现为带 `Retry-After` 的 HTTP 429，并使本次尝试不会落到另一个提供方。正确的密码会在记录失败之前先行校验，因此刚刚结束锁定的客户端第一次尝试即可成功。被跟踪的客户端数量有上限，优先淘汰最接近到期的条目，从而让生效中的锁定比陈旧计数存活更久。

尝试以提交方套接字的地址为键。在反向代理之后，所有尝试共享代理的地址，因此锁定会把该代理当作一个客户端来限流。

## 配置

| 键 | 默认值 | 含义 |
|---|---|---|
| `file` | 必填 | 凭据文件的绝对路径。Harness 状态存放位置是组合应用的装配事实，因此随附 bundle 会提供一个 Harness 主目录下的路径，部署方不应硬编码。 |
| `maxAttempts` | `5` | 触发锁定所需的同一客户端连续失败次数。 |
| `lockoutSeconds` | `300` | 触发的锁定拒绝该客户端的时长。 |

## Model Experience

None, as the password provider verifies a submitted secret for the authentication seam and registers nothing model-facing.

#### KV Cache effect

None; this package neither assembles nor sends a provider request.

## Known Limitations and Deferred Work

- **密码不能由运维方提供** —— 没有为外部选定的密钥提供配置或凭据引用路径，因此不持久化 Harness 主目录的容器每次启动都会打印新密码。接受外部密钥意味着要决定如何拒绝弱的运维方取值，而本包不解决这一问题。
- **锁定状态仅存在于进程内** —— 计数在 Harness 重启后清零，因此反复重启会清除生效中的锁定。
- **单一共享密码，没有账户体系** —— 该提供方认证的是对 Harness 凭据的持有，而不是某个人；其身份 subject 是固定标签。多用户访问是另一个提供方的职责。

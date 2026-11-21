# SSH 连接

把常用的 SSH 服务器（名称、IP/域名、端口、用户名、密码或私钥）保存在本机，之后让智能体直接查询连接表并在远端执行命令。

## 提供的工具

| 工具 | 作用 |
|---|---|
| `ssh_list` | 列出已保存的连接（名称、host、端口、用户、认证方式）。永远不返回密码。 |
| `ssh_add` | 新增或更新一条连接。给 `password` 或 `key_path` 二选一；同名覆盖需要 `overwrite: true`。 |
| `ssh_remove` | 删除连接及其保存的密码。 |
| `ssh_exec` | 在指定连接上执行远端命令，返回退出码、stdout、stderr。非零退出码是正常结果，不算工具失败。 |

典型对话：

> 把 192.168.1.10、用户 root、密码 xxx 存成 prod-web
>
> 在 prod-web 上看一下磁盘占用

智能体会依次调用 `ssh_add` 和 `ssh_exec`。

## 数据保存位置

默认在 `$DSH_HOME/ssh-connections/`（通常是 `C:\Users\<你>\.dsh\ssh-connections\`）：

- `connections.json`：连接记录，不含密码。
- `secrets/<名称>.b64`：密码的 DPAPI 密文，仅当前 Windows 用户可解密。
- `askpass.exe` / `askpass.cs`：本机编译的密码提供程序，供 OpenSSH 的 `SSH_ASKPASS` 调用。
- `ssh-connections/` 之外不会写入任何副本；密码不会落到临时文件里。

窗口配置项（`cordis.patch.yml` 的 `config`）：

| 字段 | 默认 | 含义 |
|---|---|---|
| `dataDir` | `$DSH_HOME/ssh-connections` | 自定义数据目录 |
| `connectTimeoutMs` | `15000` | 建立连接的超时 |
| `commandTimeoutMs` | `120000` | 单条命令的默认超时 |
| `outputLimitBytes` | `262144` | stdout/stderr 各自的截断上限 |
| `strictHostKeyChecking` | `accept-new` | 传给 OpenSSH 的主机密钥策略 |

## 安全说明

- 密码用 **Windows DPAPI（CurrentUser）** 加密。换一个 Windows 账户、或把文件拷到别的机器都解不开。
- 使用密码认证时，智能体通过 `SSH_ASKPASS` 把密码交给 OpenSSH，不会写临时文件、不会卡在交互式提示上。
- **主机密钥**：默认 `accept-new`，首次连接会自动记录并信任该服务器的主机密钥。如果你要严格校验，把 `strictHostKeyChecking` 改成 `yes`（必须先手工连一次把主机密钥写进 `known_hosts`）。
- `ssh_exec` 会以该 SSH 账户的权限执行你让它执行的任何命令，没有额外白名单。
- 你在对话里直接打出来的密码会留在本次会话记录中。介意的话，改完密码再补一次 `ssh_add`。

## 限制

- 依赖 Windows 自带 OpenSSH（`C:\Windows\System32\OpenSSH\ssh.exe`）与 .NET Framework 的 `csc.exe`（用于编译密码提供程序）。两者都是 Windows 10/11 的内置组件。
- 只支持单跳连接，不支持跳板机/ProxyJump 配置界面；但会读取你 `~/.ssh/config` 里的 `Host` 别名，`host` 可以直接填别名。
- 不支持密钥口令（passphrase）交互；带口令的私钥需要先用 `ssh-add` 加入 ssh-agent（当前版本也不支持 agent 转发）。
- 每个连接只保存一个密码或一把私钥，没有多套凭据轮换。

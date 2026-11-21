# SSH connections

A DeepSeek Harness bundle that stores named SSH endpoints and exposes agent tools to list, add, remove, and run commands on them.

**Windows only.** The password store uses current-user Windows DPAPI, and the askpass helper is compiled locally with the .NET Framework C# compiler. Key-based connections work without the compiler.

- `ssh_list` — saved connections without secrets
- `ssh_add` — add or update one connection (password or private key)
- `ssh_remove` — delete a connection and its stored password
- `ssh_exec` — run a remote command; returns exit code, stdout, stderr

Passwords are encrypted with current-user Windows DPAPI and handed to the Windows OpenSSH client through an `SSH_ASKPASS` helper, so no plaintext secret is written to a temporary file and no interactive prompt can hang a tool call.

Data lives in `$DSH_HOME/ssh-connections/`:

```text
connections.json     records (no secrets)
secrets/<name>.b64   DPAPI blobs, current Windows user only
askpass.cs/.exe      locally compiled password provider
```

Configuration (`cordis.patch.yml`):

| Field | Default | Meaning |
|---|---|---|
| `dataDir` | `$DSH_HOME/ssh-connections` | Custom data directory |
| `connectTimeoutMs` | `15000` | Connection establishment timeout |
| `commandTimeoutMs` | `120000` | Default per-command timeout |
| `outputLimitBytes` | `262144` | Per-stream output cap |
| `strictHostKeyChecking` | `accept-new` | OpenSSH host-key policy |

Requirements: the Windows OpenSSH client (`%SystemRoot%\System32\OpenSSH\ssh.exe`) and .NET Framework `csc.exe` for password connections. Key-based connections do not need the compiler.

See [docs/DETAIL.md](docs/DETAIL.md) for usage, security notes, and limitations.

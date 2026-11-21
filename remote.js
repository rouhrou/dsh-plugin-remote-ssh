/**
 * Runs one command through the Windows OpenSSH client.
 *
 * Key connections pass `-i` and stay non-interactive (`BatchMode=yes`).
 * Password connections stay non-interactive too: OpenSSH is told to take the
 * password from an `SSH_ASKPASS` helper that decrypts the stored DPAPI blob, so
 * no secret is written to a temporary file and no console prompt can hang the
 * tool call.
 */

import { spawn } from 'node:child_process'
import fs from 'node:fs'

const DEFAULT_OUTPUT_LIMIT = 256 * 1024

/** Absolute path of the Windows OpenSSH client, or `ssh` from PATH. */
export function sshExecutable() {
  const root = process.env.SystemRoot || 'C:\\Windows'
  const candidate = `${root}\\System32\\OpenSSH\\ssh.exe`
  return fs.existsSync(candidate) ? candidate : 'ssh'
}

/** Quote one path or word for a POSIX shell command line. */
export function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`
}

/**
 * Build the OpenSSH argument list for one saved connection.
 * @param record - stored connection record.
 * @param command - remote command line.
 * @param options - timeout, host-key policy, and optional remote directory.
 */
export function buildSshArguments(record, command, options = {}) {
  const connectTimeoutMs = options.connectTimeoutMs ?? 15000
  const strictHostKeyChecking = options.strictHostKeyChecking ?? 'accept-new'
  const args = [
    '-p', String(record.port ?? 22),
    '-o', `ConnectTimeout=${Math.max(1, Math.ceil(connectTimeoutMs / 1000))}`,
    '-o', `StrictHostKeyChecking=${strictHostKeyChecking}`,
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=3',
    '-o', 'LogLevel=ERROR',
  ]
  if (record.auth === 'key') {
    args.push('-i', record.keyPath, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes')
  } else {
    args.push(
      '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'PubkeyAuthentication=no',
      '-o', 'NumberOfPasswordPrompts=1',
      '-o', 'BatchMode=no',
    )
  }
  args.push(`${record.user}@${record.host}`)
  args.push(options.cwd ? `cd ${shellQuote(options.cwd)} && ${command}` : command)
  return args
}

/**
 * Run one remote command.
 * @returns The bounded result; the promise never rejects for command failure.
 */
export function runRemoteCommand(options) {
  const {
    record,
    command,
    cwd,
    askpassPath,
    secretFile,
    outputLimitBytes = DEFAULT_OUTPUT_LIMIT,
    timeoutMs = 120000,
    connectTimeoutMs = 15000,
    strictHostKeyChecking = 'accept-new',
    signal,
  } = options

  return new Promise((resolve) => {
    const startedAt = Date.now()
    const args = buildSshArguments(record, command, { cwd, connectTimeoutMs, strictHostKeyChecking })
    const env = { ...process.env }
    if (record.auth === 'password') {
      env.SSH_ASKPASS = askpassPath
      env.SSH_ASKPASS_REQUIRE = 'force'
      env.DSH_SSH_SECRET_FILE = secretFile
    }

    let stdout = ''
    let stderr = ''
    let truncated = false
    let timedOut = false
    let settled = false
    let timer = null

    const append = (chunk, target) => {
      const text = chunk.toString('utf8')
      const room = outputLimitBytes - target.length
      if (room <= 0) {
        truncated = true
        return
      }
      if (text.length > room) {
        truncated = true
        return target + text.slice(0, room)
      }
      return target + text
    }

    let child
    const failure = (message, durationMs) => ({
      exitCode: null,
      stdout: '',
      stderr: message,
      truncated: false,
      timedOut: false,
      durationMs,
      failure: message,
    })
    try {
      child = spawn(sshExecutable(), args, {
        env,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (error) {
      resolve(failure(error instanceof Error ? error.message : String(error), 0))
      return
    }

    const finish = (extra) => {
      if (settled) return
      settled = true
      if (timer !== null) clearTimeout(timer)
      signal?.removeEventListener?.('abort', onAbort)
      resolve({
        exitCode: extra.exitCode ?? null,
        stdout,
        stderr,
        truncated,
        timedOut,
        durationMs: Date.now() - startedAt,
        ...extra,
      })
    }

    const onAbort = () => {
      try {
        child.kill()
      } catch {
        // The child already exited.
      }
      finish({ timedOut: false, failure: 'aborted' })
    }

    child.stdout.on('data', (chunk) => {
      stdout = append(chunk, stdout)
    })
    child.stderr.on('data', (chunk) => {
      stderr = append(chunk, stderr)
    })
    child.on('error', (error) => {
      finish({ exitCode: null, failure: `cannot start the ssh client: ${error.message}` })
    })
    child.on('close', (code) => {
      finish({ exitCode: typeof code === 'number' ? code : null })
    })

    timer = setTimeout(() => {
      timedOut = true
      try {
        child.kill()
      } catch {
        // The child already exited.
      }
    }, Math.max(1000, timeoutMs))
    timer.unref?.()

    if (signal !== undefined) {
      if (signal.aborted) {
        onAbort()
        return
      }
      signal.addEventListener?.('abort', onAbort, { once: true })
    }
  })
}

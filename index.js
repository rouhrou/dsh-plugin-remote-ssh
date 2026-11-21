/**
 * SSH connections bundle, Host half.
 *
 * Stores named SSH endpoints (host, port, user, password or key) outside the
 * workspace, protects passwords with current-user Windows DPAPI, and exposes
 * four model-facing tools: ssh_list, ssh_add, ssh_remove, ssh_exec.
 */

import path from 'node:path'

import { ConnectionStore, dshHome } from './store.js'
import { runRemoteCommand } from './remote.js'

export const name = 'ssh-connections'
export const inject = ['tools']

const HOST_KEY_POLICIES = new Set(['accept-new', 'yes', 'no', 'ask'])

/** Resolve and clamp the bundle configuration. */
export function resolveSettings(config = {}) {
  const dataDir = typeof config.dataDir === 'string' && config.dataDir.length > 0
    ? path.resolve(config.dataDir)
    : path.join(dshHome(), 'ssh-connections')
  return {
    dataDir,
    connectTimeoutMs: clampInteger(config.connectTimeoutMs, 15000, 1000, 300000),
    commandTimeoutMs: clampInteger(config.commandTimeoutMs, 120000, 1000, 3600000),
    outputLimitBytes: clampInteger(config.outputLimitBytes, 256 * 1024, 4096, 4 * 1024 * 1024),
    strictHostKeyChecking: HOST_KEY_POLICIES.has(config.strictHostKeyChecking)
      ? config.strictHostKeyChecking
      : 'accept-new',
  }
}

function clampInteger(value, fallback, min, max) {
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(max, Math.max(min, Math.round(number)))
}

const text = (value) => [{ type: 'text', text: value }]

/** Build the four tool definitions bound to one store. */
export function buildTools(store, settings) {
  const listSchema = {
    type: 'object',
    properties: {
      connections: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            host: { type: 'string' },
            port: { type: 'integer' },
            user: { type: 'string' },
            auth: { type: 'string', enum: ['password', 'key'] },
            keyPath: { type: 'string' },
            note: { type: 'string' },
            hasPassword: { type: 'boolean' },
          },
          required: ['name', 'host', 'port', 'user', 'auth', 'hasPassword'],
          additionalProperties: false,
        },
      },
    },
    required: ['connections'],
    additionalProperties: false,
  }

  return [
    {
      name: 'ssh_list',
      description: 'List the SSH connections saved on this machine: name, host, port, user, and authentication type. Passwords are never returned. Use a returned name with ssh_exec.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: {
        schema: listSchema,
        render(_args, value) {
          if (value.connections.length === 0) return text('No saved SSH connections. Add one with ssh_add.')
          const lines = value.connections.map((entry) => {
            const auth = entry.auth === 'key' ? `key ${entry.keyPath}` : (entry.hasPassword ? 'password' : 'password (missing)')
            const note = entry.note ? `, ${entry.note}` : ''
            return `- ${entry.name}: ${entry.user}@${entry.host}:${entry.port} (${auth}${note})`
          })
          return text([`${value.connections.length} saved SSH connection${value.connections.length === 1 ? '' : 's'}:`, ...lines].join('\n'))
        },
      },
      async execute() {
        const connections = store.list().map((record) => {
          const entry = {
            name: record.name,
            host: record.host,
            port: record.port ?? 22,
            user: record.user,
            auth: record.auth === 'key' ? 'key' : 'password',
            hasPassword: record.auth === 'key' ? false : store.hasSecret(record.name),
          }
          if (record.auth === 'key' && record.keyPath) entry.keyPath = record.keyPath
          if (record.note) entry.note = record.note
          return entry
        })
        return { connections }
      },
    },

    {
      name: 'ssh_add',
      description: 'Save or update an SSH connection so later tool calls can reach that server. Pass a password (encrypted for this Windows account only) or a private key path. Reusing an existing name fails unless overwrite is true.',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Short handle used by ssh_exec, such as "prod-web".' },
          host: { type: 'string', description: 'Hostname or IP address.' },
          user: { type: 'string', description: 'SSH user name.' },
          port: { type: 'integer', description: 'TCP port; defaults to 22.' },
          password: { type: 'string', description: 'Password to protect and store. Omit when using key_path or when updating a record that already has one.' },
          key_path: { type: 'string', description: 'Absolute path of a private key file, such as C:\\Users\\me\\.ssh\\id_ed25519.' },
          note: { type: 'string', description: 'Free-form reminder, such as "production database host".' },
          overwrite: { type: 'boolean', description: 'Replace an existing connection with the same name.' },
        },
        required: ['name', 'host', 'user'],
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            host: { type: 'string' },
            port: { type: 'integer' },
            user: { type: 'string' },
            auth: { type: 'string', enum: ['password', 'key'] },
            created: { type: 'boolean' },
            hasPassword: { type: 'boolean' },
          },
          required: ['name', 'host', 'port', 'user', 'auth', 'created', 'hasPassword'],
          additionalProperties: false,
        },
        render(_args, value) {
          const auth = value.auth === 'key' ? 'key' : 'password'
          return text(`${value.created ? 'Saved' : 'Updated'} "${value.name}" (${value.user}@${value.host}:${value.port}, ${auth}).`)
        },
      },
      async execute(args) {
        const existing = store.get(args.name)
        if (existing !== undefined && args.overwrite !== true) {
          throw new Error(`connection "${args.name}" already exists; pass overwrite: true to replace it`)
        }
        const wantsKey = typeof args.key_path === 'string' && args.key_path.length > 0
        const password = typeof args.password === 'string' && args.password.length > 0 ? args.password : undefined
        if (!wantsKey && password === undefined) {
          if (!(existing && existing.auth === 'password' && store.hasSecret(existing.name))) {
            throw new Error('provide either password or key_path so the connection can authenticate')
          }
        }
        const { record, created } = store.upsert(
          {
            name: args.name,
            host: args.host,
            port: args.port,
            user: args.user,
            auth: wantsKey ? 'key' : 'password',
            keyPath: wantsKey ? args.key_path : null,
            note: args.note,
          },
          password,
        )
        if (wantsKey) store.clearSecret(record.name)
        return {
          name: record.name,
          host: record.host,
          port: record.port,
          user: record.user,
          auth: record.auth,
          created,
          hasPassword: record.auth === 'password' && store.hasSecret(record.name),
        }
      },
    },

    {
      name: 'ssh_remove',
      description: 'Delete a saved SSH connection and its stored password.',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Name of the connection to delete.' },
        },
        required: ['name'],
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            removed: { type: 'boolean' },
          },
          required: ['name', 'removed'],
          additionalProperties: false,
        },
        render(_args, value) {
          return text(value.removed ? `Removed "${value.name}".` : `No saved connection named "${value.name}".`)
        },
      },
      async execute(args) {
        return { name: args.name, removed: store.remove(args.name) }
      },
    },

    {
      name: 'ssh_exec',
      description: 'Run a shell command on a saved SSH connection and return its exit code, stdout, and stderr. Output is capped; a non-zero exit code is a normal result, not a tool failure.',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Saved connection name from ssh_list.' },
          command: { type: 'string', description: 'Remote command line, run by the remote user\'s shell.' },
          cwd: { type: 'string', description: 'Remote directory to change into before running the command.' },
          timeout_ms: { type: 'integer', description: 'Abort the call after this many milliseconds.' },
        },
        required: ['name', 'command'],
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            exitCode: { oneOf: [{ type: 'integer' }, { type: 'null' }] },
            stdout: { type: 'string' },
            stderr: { type: 'string' },
            truncated: { type: 'boolean' },
            timedOut: { type: 'boolean' },
            durationMs: { type: 'integer' },
            aborted: { type: 'boolean' },
          },
          required: ['name', 'exitCode', 'stdout', 'stderr', 'truncated', 'timedOut', 'durationMs', 'aborted'],
          additionalProperties: false,
        },
        render(_args, value) {
          const head = `${value.name}: exit ${value.exitCode === null ? 'none' : value.exitCode}`
            + `${value.timedOut ? ' (timed out)' : ''} in ${value.durationMs}ms`
          const parts = [head]
          if (value.stdout.length > 0) parts.push(`--- stdout ---\n${value.stdout.replace(/\n$/, '')}`)
          if (value.stderr.length > 0) parts.push(`--- stderr ---\n${value.stderr.replace(/\n$/, '')}`)
          if (value.stdout.length === 0 && value.stderr.length === 0) parts.push('(no output)')
          if (value.truncated) parts.push('(output truncated)')
          return text(parts.join('\n'))
        },
      },
      async execute(args, exec) {
        const record = store.get(args.name)
        if (record === undefined) {
          throw new Error(`no saved SSH connection named "${args.name}"; call ssh_list to see saved names`)
        }
        let askpassPath
        if (record.auth === 'key') {
          askpassPath = undefined
        } else {
          if (!store.hasSecret(record.name)) {
            throw new Error(`connection "${record.name}" has no stored password; add one with ssh_add and overwrite: true`)
          }
          askpassPath = store.ensureHelper()
        }
        const result = await runRemoteCommand({
          record,
          command: args.command,
          cwd: args.cwd,
          askpassPath,
          secretFile: store.secretFile(record.name),
          outputLimitBytes: settings.outputLimitBytes,
          timeoutMs: clampInteger(args.timeout_ms, settings.commandTimeoutMs, 1000, 3600000),
          connectTimeoutMs: settings.connectTimeoutMs,
          strictHostKeyChecking: settings.strictHostKeyChecking,
          signal: exec.signal,
        })
        if (result.failure !== undefined && result.failure !== 'aborted') {
          throw new Error(result.failure)
        }
        return {
          name: record.name,
          exitCode: result.exitCode,
          stdout: result.stdout,
          stderr: result.stderr,
          truncated: result.truncated,
          timedOut: result.timedOut,
          durationMs: result.durationMs,
          aborted: result.failure === 'aborted',
        }
      },
    },
  ]
}

/** Register the SSH connection tools on the tool registry. */
export function apply(ctx, config = {}) {
  const settings = resolveSettings(config)
  const store = new ConnectionStore(settings.dataDir)
  for (const definition of buildTools(store, settings)) {
    ctx.tools.register(definition)
  }
}

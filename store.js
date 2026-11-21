/**
 * Connection records and Windows DPAPI-protected passwords for the SSH
 * connections bundle. Records live in `<dataDir>/connections.json`; each
 * password is a base64 DPAPI blob in `<dataDir>/secrets/<name>.b64` that only
 * the current Windows account can decrypt.
 */

import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const STORE_VERSION = 1

/** Absolute DSH home directory used for default plugin data. */
export function dshHome() {
  return process.env.DSH_HOME ? path.resolve(process.env.DSH_HOME) : path.join(os.homedir(), '.dsh')
}

/** Reject connection names that cannot be used as a file name. */
export function assertConnectionName(name) {
  if (typeof name !== 'string' || !NAME_PATTERN.test(name)) {
    throw new Error(
      `connection name must be 1-64 characters of letters, digits, dot, dash, or underscore (got ${JSON.stringify(name)})`,
    )
  }
  return name
}

/** Reject a host or user that is empty or obviously malformed for OpenSSH. */
export function assertHost(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) {
    throw new Error(`${label} must be a non-empty string of at most 255 characters`)
  }
  if (/[\s@]/.test(value)) {
    throw new Error(`${label} must not contain whitespace or "@" (got ${JSON.stringify(value)})`)
  }
  return value
}

/** One saved connection as stored on disk. */
export function normalizeRecord(input) {
  const record = {
    name: assertConnectionName(input.name),
    host: assertHost(input.host, 'host'),
    port: normalizePort(input.port),
    user: assertHost(input.user, 'user'),
    auth: input.auth === 'key' ? 'key' : 'password',
    keyPath: input.auth === 'key' ? normalizeKeyPath(input.keyPath) : null,
    note: typeof input.note === 'string' && input.note.length > 0 ? input.note.slice(0, 500) : null,
    createdAt: typeof input.createdAt === 'string' ? input.createdAt : new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    hostKey: typeof input.hostKey === 'string' ? input.hostKey : null,
  }
  if (record.auth === 'key' && !fs.existsSync(record.keyPath)) {
    throw new Error(`keyPath ${JSON.stringify(record.keyPath)} does not exist`)
  }
  return record
}

function normalizeKeyPath(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('keyPath is required when auth is "key"')
  }
  const expanded = value.startsWith('~/') ? path.join(os.homedir(), value.slice(2)) : value
  return path.resolve(expanded)
}

function normalizePort(value) {
  if (value === undefined || value === null || value === '') return 22
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`port must be an integer from 1 through 65535 (got ${JSON.stringify(value)})`)
  }
  return port
}

/** Locate `csc.exe` from the installed .NET Framework. */
function findCsc() {
  const root = process.env.SystemRoot || 'C:\\Windows'
  const candidates = [
    path.join(root, 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe'),
    path.join(root, 'Microsoft.NET', 'Framework', 'v4.0.30319', 'csc.exe'),
  ]
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? null
}

/** Durable store for connection records and their encrypted passwords. */
export class ConnectionStore {
  constructor(dataDir) {
    this.dir = path.resolve(dataDir)
    this.file = path.join(this.dir, 'connections.json')
    this.secretsDir = path.join(this.dir, 'secrets')
    this.helperSource = path.join(this.dir, 'askpass.cs')
    this.helperExe = path.join(this.dir, 'askpass.exe')
    this.packageSource = path.join(path.dirname(fileURLToPath(import.meta.url)), 'askpass.cs')
  }

  /** Create the data directories; safe to call repeatedly. */
  ensureLayout() {
    fs.mkdirSync(this.secretsDir, { recursive: true })
  }

  /** Read every stored record, tolerating a missing or unreadable file. */
  read() {
    try {
      const raw = fs.readFileSync(this.file, 'utf8')
      const parsed = JSON.parse(raw)
      const connections = Array.isArray(parsed?.connections) ? parsed.connections : []
      return connections.filter((record) => record && typeof record.name === 'string')
    } catch (error) {
      if (error && error.code === 'ENOENT') return []
      throw new Error(`cannot read ${this.file}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  /** Persist the record list atomically. */
  write(connections) {
    this.ensureLayout()
    const payload = JSON.stringify({ version: STORE_VERSION, connections }, null, 2)
    const temporary = `${this.file}.tmp`
    fs.writeFileSync(temporary, payload, 'utf8')
    fs.renameSync(temporary, this.file)
  }

  /** Every saved record in insertion order. */
  list() {
    return this.read()
  }

  /** One record by name, or undefined. */
  get(name) {
    return this.read().find((record) => record.name === name)
  }

  /** Path of the encrypted password blob for a connection. */
  secretFile(name) {
    return path.join(this.secretsDir, `${assertConnectionName(name)}.b64`)
  }

  /** Whether a stored password blob exists. */
  hasSecret(name) {
    return fs.existsSync(this.secretFile(name))
  }

  /**
   * Insert or update one record.
   * @returns `{ record, created }`
   */
  upsert(input, password) {
    const existing = this.get(input.name)
    const record = normalizeRecord({ ...input, createdAt: existing?.createdAt })
    const connections = this.read().filter((entry) => entry.name !== record.name)
    connections.push(record)
    if (typeof password === 'string' && password.length > 0) {
      this.ensureLayout()
      fs.writeFileSync(this.secretFile(record.name), this.protect(password), 'ascii')
    }
    this.write(connections)
    return { record, created: existing === undefined }
  }

  /** Delete one record and its stored secret. */
  remove(name) {
    assertConnectionName(name)
    const connections = this.read()
    const next = connections.filter((record) => record.name !== name)
    if (next.length === connections.length) return false
    this.write(next)
    try {
      fs.rmSync(this.secretFile(name), { force: true })
    } catch {
      // A missing or locked secret must not keep a removed record alive.
    }
    return true
  }

  /** Drop a stored password without touching the record. */
  clearSecret(name) {
    fs.rmSync(this.secretFile(name), { force: true })
  }

  /** Ensure the compiled DPAPI helper exists and return its path. */
  ensureHelper() {
    this.ensureLayout()
    if (!fs.existsSync(this.helperSource)) {
      if (!fs.existsSync(this.packageSource)) {
        throw new Error(`DPAPI helper source is missing from the plugin package (${this.packageSource})`)
      }
      fs.copyFileSync(this.packageSource, this.helperSource)
    }
    const sourceStat = fs.statSync(this.helperSource)
    if (fs.existsSync(this.helperExe)) {
      const exeStat = fs.statSync(this.helperExe)
      if (exeStat.mtimeMs >= sourceStat.mtimeMs && exeStat.size > 0) return this.helperExe
    }
    const csc = findCsc()
    if (csc === null) {
      throw new Error(
        'cannot compile the DPAPI helper: csc.exe from the .NET Framework was not found. '
        + 'Password-protected connections need it; key-based connections do not.',
      )
    }
    const result = spawnSync(
      csc,
      ['/nologo', '/target:exe', '/optimize+', '/reference:System.Security.dll', `/out:${this.helperExe}`, this.helperSource],
      { encoding: 'utf8', timeout: 120000, windowsHide: true },
    )
    if (result.status !== 0 || !fs.existsSync(this.helperExe)) {
      const detail = result.error !== undefined
        ? String(result.error)
        : ((result.stderr || result.stdout || '').trim() || `exit ${result.status}`)
      throw new Error(`cannot compile the DPAPI helper with ${csc}: ${detail}`)
    }
    return this.helperExe
  }

  /** Encrypt one password into its base64 DPAPI blob. */
  protect(password) {
    const result = this.runHelper('--protect', Buffer.from(password, 'utf8').toString('base64'))
    return result
  }

  /** Decrypt one base64 DPAPI blob back to its plaintext password. */
  unprotect(blob) {
    return Buffer.from(this.runHelper('--unprotect', blob), 'base64').toString('utf8')
  }

  /** Read and decrypt a connection's stored password. */
  readSecret(name) {
    const file = this.secretFile(name)
    if (!fs.existsSync(file)) return null
    return this.unprotect(fs.readFileSync(file, 'ascii').trim())
  }

  runHelper(mode, stdin) {
    const exe = this.ensureHelper()
    const result = spawnSync(exe, [mode], {
      input: stdin,
      timeout: 30000,
      windowsHide: true,
    })
    if (result.status !== 0) {
      const detail = result.error !== undefined
        ? String(result.error)
        : ((result.stderr ? Buffer.from(result.stderr).toString('utf8').trim() : '') || `exit ${result.status}`)
      throw new Error(`DPAPI helper ${mode} failed: ${detail}`)
    }
    return Buffer.from(result.stdout ?? []).toString('ascii').trim()
  }
}

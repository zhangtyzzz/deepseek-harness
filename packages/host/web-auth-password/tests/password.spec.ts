/** Behavior of the local-password provider: credential generation, storage, verification, and lockout. */

import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import InvariantRegistry from '@deepseek-ai/dsh-invariants'
import WebAuth from '@deepseek-ai/dsh-host-web-auth'
import * as PasswordInvariant from '../src/invariant.ts'
import { generatePassword, loadOrCreateCredential, verifyPassword } from '../src/credential-file.ts'
import { PasswordAuthProvider, PASSWORD_PROVIDER_ID } from '../src/provider.ts'
import { apply, inject, name } from '../src/index.ts'

let root: string

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'dsh-web-auth-password-'))
})

afterEach(async () => {
  await rm(root, { recursive: true, force: true })
})

describe('generated password', () => {
  it('draws 125 bits from an unambiguous 32-symbol alphabet', () => {
    const password = generatePassword()
    expect(password).toMatch(/^[A-HJ-KM-NP-TV-Z0-9]{5}(-[A-HJ-KM-NP-TV-Z0-9]{5}){4}$/)
    // The confusable letters are absent, which is what makes 0 and 1 safe to include.
    expect(password).not.toMatch(/[ILOU]/)
    // Distinct across calls: this is the deployment's only credential.
    expect(new Set(Array.from({ length: 32 }, () => generatePassword())).size).toBe(32)
  })
})

describe('credential file', () => {
  it('generates on first load, persists only a verifier, and never regenerates', async () => {
    const file = join(root, 'nested', 'password.json')
    const first = await loadOrCreateCredential(file)
    expect(first.generated).toMatch(/^[A-HJ-KM-NP-TV-Z0-9-]+$/)

    const text = await readFile(file, 'utf8')
    // The password itself must never reach disk.
    expect(text).not.toContain(first.generated!)
    expect(JSON.parse(text)).toMatchObject({ version: 1, algorithm: 'scrypt' })

    const second = await loadOrCreateCredential(file)
    expect(second.generated).toBeUndefined()
    expect(second.credential).toEqual(first.credential)
    expect(await verifyPassword(first.generated!, second.credential)).toBe(true)
  })

  it('creates the file owner-readable only', async () => {
    const file = join(root, 'password.json')
    await loadOrCreateCredential(file)
    // Windows does not model POSIX mode bits; the assertion is meaningful only
    // where the platform enforces them.
    if (process.platform !== 'win32') {
      expect((await stat(file)).mode & 0o777).toBe(0o600)
    }
  })

  it('verifies the generated password and rejects everything else', async () => {
    const { credential, generated } = await loadOrCreateCredential(join(root, 'password.json'))
    expect(await verifyPassword(generated!, credential)).toBe(true)
    expect(await verifyPassword('', credential)).toBe(false)
    expect(await verifyPassword(`${generated!}x`, credential)).toBe(false)
    expect(await verifyPassword(generated!.toLowerCase(), credential)).toBe(false)
  })

  it('reads a credential written by a first-start race instead of overwriting it', async () => {
    const file = join(root, 'password.json')
    // Concurrent first starts: each reads an absent file, then all but one lose
    // the exclusive create and must adopt the winner's credential rather than
    // invalidating a password it has already printed.
    const racers = await Promise.all(Array.from({ length: 4 }, () => loadOrCreateCredential(file)))
    const generated = racers.filter(result => result.generated !== undefined)
    expect(generated).toHaveLength(1)
    for (const result of racers) {
      expect(result.credential).toEqual(generated[0]!.credential)
      expect(await verifyPassword(generated[0]!.generated!, result.credential)).toBe(true)
    }
  })

  it('fails loud on a format this build does not write', async () => {
    const file = join(root, 'password.json')
    await writeFile(file, JSON.stringify({ version: 99, algorithm: 'scrypt' }))
    await expect(loadOrCreateCredential(file)).rejects.toThrow(/credential version 99/)

    await writeFile(file, JSON.stringify({ version: 1, algorithm: 'bcrypt' }))
    await expect(loadOrCreateCredential(file)).rejects.toThrow(/unsupported algorithm/)

    await writeFile(file, 'not json')
    await expect(loadOrCreateCredential(file)).rejects.toThrow(/is not valid JSON/)
  })

  it('propagates a read failure rather than silently minting a second credential', async () => {
    // A directory at the credential path fails with EISDIR, not ENOENT: an
    // unreadable credential must never look like an absent one, or the harness
    // would print a new password while the old one still verifies elsewhere.
    await expect(loadOrCreateCredential(root)).rejects.toThrow()
  })

  // POSIX permissions only, and only when they actually bind: a root-owned run
  // ignores the read-only bit, and Windows does not model it.
  const canTestUnwritableDirectory = process.platform !== 'win32' && process.getuid?.() !== 0
  it.skipIf(!canTestUnwritableDirectory)('propagates a write failure that is not a lost create race', async () => {
    const directory = join(root, 'readonly')
    await mkdir(directory)
    await chmod(directory, 0o500)
    try {
      // The credential is absent (so the read reports ENOENT) but the write
      // cannot land. That is not a lost race, so it must surface rather than
      // being mistaken for another process having won.
      await expect(loadOrCreateCredential(join(directory, 'password.json'))).rejects.toThrow()
    } finally {
      await chmod(directory, 0o700)
    }
  })
})

describe('lockout', () => {
  /** Provider over a real credential, with a controllable clock. */
  async function provider(options: {
    maxAttempts?: number
    lockoutSeconds?: number
    maxTrackedClients?: number
  } = {}): Promise<{
    provider: PasswordAuthProvider
    password: string
    advance: (seconds: number) => void
  }> {
    const { credential, generated } = await loadOrCreateCredential(join(root, 'password.json'))
    let now = 1_000_000
    return {
      password: generated!,
      advance: (seconds) => { now += seconds * 1000 },
      provider: new PasswordAuthProvider({
        credential,
        maxAttempts: options.maxAttempts ?? 3,
        lockoutSeconds: options.lockoutSeconds ?? 60,
        ...options.maxTrackedClients !== undefined && { maxTrackedClients: options.maxTrackedClients },
        now: () => now,
      }),
    }
  }

  it('verifies the right password and reports the provider identity', async () => {
    const { provider: subject, password } = await provider()
    expect(await subject.verifySecret(password, { address: '10.0.0.9' })).toEqual({
      outcome: 'verified',
      identity: { provider: PASSWORD_PROVIDER_ID, subject: 'local-password' },
    })
  })

  it('locks a client after the configured consecutive failures and reports the wait', async () => {
    const { provider: subject, password, advance } = await provider({ maxAttempts: 3, lockoutSeconds: 60 })
    const client = { address: '10.0.0.9' }
    expect(await subject.verifySecret('wrong', client)).toEqual({ outcome: 'rejected' })
    expect(await subject.verifySecret('wrong', client)).toEqual({ outcome: 'rejected' })
    // The third failure trips the lockout; the fourth attempt is refused unjudged.
    expect(await subject.verifySecret('wrong', client)).toEqual({ outcome: 'rejected' })
    expect(await subject.verifySecret(password, client)).toEqual({ outcome: 'locked', retryAfterSeconds: 60 })

    advance(30)
    expect(await subject.verifySecret(password, client)).toEqual({ outcome: 'locked', retryAfterSeconds: 30 })
    // Once it expires the correct password works on the FIRST attempt: the
    // lockout must not have consumed the client's fresh budget.
    advance(31)
    expect(await subject.verifySecret(password, client)).toMatchObject({ outcome: 'verified' })
  })

  it('starts the count over after an expired lockout instead of locking on one failure', async () => {
    const { provider: subject, advance } = await provider({ maxAttempts: 3, lockoutSeconds: 60 })
    const client = { address: '10.0.0.9' }
    for (let attempt = 0; attempt < 3; attempt += 1) await subject.verifySecret('wrong', client)
    advance(61)
    expect(await subject.verifySecret('wrong', client)).toEqual({ outcome: 'rejected' })
    expect(await subject.verifySecret('wrong', client)).toEqual({ outcome: 'rejected' })
  })

  it('resets a client on success, so earlier failures cannot accumulate into a lockout', async () => {
    const { provider: subject, password } = await provider({ maxAttempts: 3 })
    const client = { address: '10.0.0.9' }
    await subject.verifySecret('wrong', client)
    await subject.verifySecret('wrong', client)
    expect(await subject.verifySecret(password, client)).toMatchObject({ outcome: 'verified' })
    await subject.verifySecret('wrong', client)
    await subject.verifySecret('wrong', client)
    expect(await subject.verifySecret(password, client)).toMatchObject({ outcome: 'verified' })
  })

  it('keys on the client, so one attacker cannot lock another client out', async () => {
    const { provider: subject, password } = await provider({ maxAttempts: 2 })
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await subject.verifySecret('wrong', { address: '10.0.0.9' })
    }
    expect(await subject.verifySecret(password, { address: '10.0.0.9' })).toMatchObject({ outcome: 'locked' })
    expect(await subject.verifySecret(password, { address: '10.0.0.10' })).toMatchObject({ outcome: 'verified' })
  })

  it('tracks address-less clients as one bucket', async () => {
    const { provider: subject, password } = await provider({ maxAttempts: 2 })
    await subject.verifySecret('wrong', {})
    await subject.verifySecret('wrong', {})
    expect(await subject.verifySecret(password, {})).toMatchObject({ outcome: 'locked' })
  })

  it('locks on the first failure when the threshold is one attempt', async () => {
    const { provider: subject, password } = await provider({ maxAttempts: 1, lockoutSeconds: 60 })
    const client = { address: '10.0.0.9' }
    expect(await subject.verifySecret('wrong', client)).toEqual({ outcome: 'rejected' })
    expect(await subject.verifySecret(password, client)).toEqual({ outcome: 'locked', retryAfterSeconds: 60 })
  })

  it('sheds unlocked counters before an in-force lockout when the table is full', async () => {
    const { provider: subject, password } = await provider({
      maxAttempts: 5,
      lockoutSeconds: 600,
      maxTrackedClients: 3,
    })
    const locked = { address: 'held' }
    for (let attempt = 0; attempt < 5; attempt += 1) await subject.verifySecret('wrong', locked)
    // Each of these is one failure, so they sit unlocked — exactly the stale
    // counters eviction should reclaim first.
    for (const address of ['a', 'b', 'c', 'd', 'e']) {
      await subject.verifySecret('wrong', { address })
    }
    expect(await subject.verifySecret(password, locked)).toMatchObject({ outcome: 'locked' })
  })

  it('evicts the soonest-expiring lockout when every tracked client is locked', async () => {
    const { provider: subject, password, advance } = await provider({
      maxAttempts: 1,
      lockoutSeconds: 60,
      maxTrackedClients: 2,
    })
    const earliest = { address: 'earliest' }
    await subject.verifySecret('wrong', earliest)
    advance(10)
    await subject.verifySecret('wrong', { address: 'later' })
    // The table is full and both entries are locked; the new failure forces the
    // least valuable eviction, which is the lockout expiring soonest.
    await subject.verifySecret('wrong', { address: 'newest' })
    expect(await subject.verifySecret(password, earliest)).toMatchObject({ outcome: 'verified' })
    expect(await subject.verifySecret(password, { address: 'later' })).toMatchObject({ outcome: 'locked' })
  })
})

describe('password plugin', () => {
  it('registers the provider and announces a freshly generated password once', async () => {
    const printed: string[] = []
    const log = vi.spyOn(console, 'log').mockImplementation((line: unknown) => { printed.push(String(line)) })
    try {
      const file = join(root, 'password.json')
      const ctx = new Context()
      await ctx.plugin(WebAuth)
      const fiber = ctx.plugin({ name, inject: [...inject], apply }, { file, maxAttempts: 5, lockoutSeconds: 300 })
      await fiber.await()
      expect(ctx.webAuth.required).toBe(true)
      expect(ctx.webAuth.interactive).toBe(true)

      const announcement = printed.join('\n')
      const password = /Password: (\S+)/.exec(announcement)?.[1]
      expect(password).toMatch(/^[A-HJ-KM-NP-TV-Z0-9-]+$/)
      expect(announcement).toContain(file)
      // The announced password is the one the mounted provider accepts.
      expect(await ctx.webAuth.signIn(password!, {}, { headers: {} })).toMatchObject({ outcome: 'verified' })

      await fiber.dispose()
      expect(ctx.webAuth.required).toBe(false)

      // A restart against the same file announces nothing: the password is
      // recoverable only from the first run's output.
      printed.length = 0
      const restarted = ctx.plugin({ name, inject: [...inject], apply }, { file })
      await restarted.await()
      expect(printed).toEqual([])
      expect(await ctx.webAuth.signIn(password!, {}, { headers: {} })).toMatchObject({ outcome: 'verified' })
      await restarted.dispose()
      await ctx.fiber.dispose()
    } finally {
      log.mockRestore()
    }
  })

  it('reserves package ownership without installing a session check', async () => {
    const ctx = new Context()
    await ctx.plugin(InvariantRegistry)
    await expect(ctx.plugin(PasswordInvariant).then(() => undefined)).resolves.toBeUndefined()
    await ctx.fiber.dispose()
  })
})

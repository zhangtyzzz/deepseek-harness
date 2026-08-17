/**
 * The password provider's on-disk credential: a scrypt verifier for one
 * generated password, never the password itself.
 *
 * The file is created on first start with owner-only permissions and an
 * exclusive create, so two processes racing a fresh harness home converge on
 * one credential instead of silently overwriting each other. Its `version` is
 * checked on read and a mismatch fails loud — this repository rejects old
 * on-disk formats rather than migrating them.
 * @module @deepseek-ai/dsh-host-web-auth-password/credential-file
 */

import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'

/** Only format this package writes or accepts. */
const CREDENTIAL_VERSION = 1

/**
 * scrypt cost. `N * r * 128` bytes (16 MiB here) stays under Node's default
 * `maxmem`, so no call-site override is needed. The stored password is
 * high-entropy and machine-generated, so this KDF defends a disclosed file
 * against inspection rather than against guessing a human-chosen secret.
 */
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 32 } as const

/**
 * Alphabet for generated passwords: 32 symbols, so one random byte maps to one
 * symbol with no modulo bias. `I`, `L`, `O` and `U` are absent, which both
 * removes transcription ambiguity when reading a password off a terminal and
 * makes the digits `0` and `1` unambiguous in turn.
 */
const PASSWORD_ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ0123456789'

/** Symbols per group and group count: 25 symbols, 125 bits of entropy. */
const PASSWORD_GROUPS = 5
const PASSWORD_GROUP_SIZE = 5

/** The persisted verifier. Field types are as READ from disk, so validation is meaningful. */
interface CredentialFile {
  readonly version: number
  readonly algorithm: string
  readonly params: { readonly N: number; readonly r: number; readonly p: number; readonly keylen: number }
  readonly salt: string
  readonly hash: string
  readonly createdAt: string
}

/** A loaded verifier plus the password when this process just generated it. */
export interface LoadedCredential {
  /** Verifier for {@link verifyPassword}. */
  readonly credential: CredentialFile
  /**
   * The generated password, present only when this call created the file. The
   * caller must deliver it to the operator; it is never recoverable later.
   */
  readonly generated?: string
}

/**
 * Generate a readable high-entropy password.
 * @returns hyphen-grouped symbols drawn uniformly from {@link PASSWORD_ALPHABET}.
 */
export function generatePassword(): string {
  const bytes = randomBytes(PASSWORD_GROUPS * PASSWORD_GROUP_SIZE)
  const symbols = [...bytes].map(byte => PASSWORD_ALPHABET[byte % PASSWORD_ALPHABET.length])
  return Array.from(
    { length: PASSWORD_GROUPS },
    (_unused, group) => symbols.slice(group * PASSWORD_GROUP_SIZE, (group + 1) * PASSWORD_GROUP_SIZE).join(''),
  ).join('-')
}

async function derive(password: string, salt: Buffer, params: CredentialFile['params']): Promise<Buffer> {
  // Promisified by hand: `scrypt`'s overloads defeat `util.promisify`'s typing
  // once the options argument is supplied.
  return await new Promise<Buffer>((resolve, reject) => {
    scrypt(password, salt, params.keylen, { N: params.N, r: params.r, p: params.p }, (error, derived) => {
      /* v8 ignore next -- error arm: the cost parameters are this module's own
      constants or were read back from a file it wrote, so scrypt cannot reject
      them at runtime. */
      if (error !== null) reject(error)
      else resolve(derived)
    })
  })
}

function assertSupported(credential: CredentialFile, file: string): void {
  if (credential.version !== CREDENTIAL_VERSION) {
    throw new Error(
      `web-auth-password: ${file} has credential version ${String(credential.version)}, `
      + `this build writes ${String(CREDENTIAL_VERSION)}; delete the file to generate a new password`,
    )
  }
  if (credential.algorithm !== 'scrypt') {
    throw new Error(`web-auth-password: ${file} names unsupported algorithm ${JSON.stringify(credential.algorithm)}`)
  }
}

/**
 * Load the credential, generating one on first start.
 * @param file - absolute path of the credential file.
 * @returns the verifier, plus the generated password when this call created it.
 */
export async function loadOrCreateCredential(file: string): Promise<LoadedCredential> {
  const existing = await readCredential(file)
  if (existing !== undefined) return { credential: existing }

  const password = generatePassword()
  const salt = randomBytes(16)
  const credential: CredentialFile = {
    version: CREDENTIAL_VERSION,
    algorithm: 'scrypt',
    params: SCRYPT_PARAMS,
    salt: salt.toString('base64'),
    hash: (await derive(password, salt, SCRYPT_PARAMS)).toString('base64'),
    createdAt: new Date().toISOString(),
  }
  await mkdir(dirname(file), { recursive: true, mode: 0o700 })
  try {
    // Exclusive create: the loser of a first-start race reads the winner's
    // credential instead of invalidating the password it already printed.
    await writeFile(file, `${JSON.stringify(credential, undefined, 2)}\n`, { mode: 0o600, flag: 'wx' })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
    const winner = await readCredential(file)
    /* v8 ignore next -- `undefined` arm: the exclusive create just reported the
    file exists, so it is absent again only if something deleted it in between. */
    if (winner === undefined) throw error
    return { credential: winner }
  }
  return { credential, generated: password }
}

/** Read and validate the credential file, or undefined when it does not exist. */
async function readCredential(file: string): Promise<CredentialFile | undefined> {
  let text: string
  try {
    text = await readFile(file, 'utf8')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
    throw error
  }
  let parsed: CredentialFile
  try {
    parsed = JSON.parse(text) as CredentialFile
  } catch (error) {
    throw new Error(`web-auth-password: ${file} is not valid JSON: ${String(error)}`)
  }
  assertSupported(parsed, file)
  return parsed
}

/**
 * Verify a submitted password against a loaded credential.
 * @param submitted - the password presented by the caller.
 * @param credential - the loaded verifier.
 * @returns whether the password matches.
 */
export async function verifyPassword(submitted: string, credential: LoadedCredential['credential']): Promise<boolean> {
  const expected = Buffer.from(credential.hash, 'base64')
  const actual = await derive(submitted, Buffer.from(credential.salt, 'base64'), credential.params)
  // Equal by construction: both are `params.keylen` long, so the comparison
  // never throws on width and stays constant-time over the digest.
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}

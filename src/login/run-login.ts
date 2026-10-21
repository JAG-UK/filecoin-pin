/**
 * Action handler for `filecoin-pin login`.
 *
 * Generates (or resumes) a session key, saves it before anything else
 * happens, prints and opens the console link where the wallet owner
 * approves the key, waits for the grant on-chain, then prints the granted
 * scopes and the account readiness scorecard. Every printed line is part
 * of the interface: scripts read this output as well as people, so change
 * wording together with the tests that pin it.
 *
 * Exit codes: 0 when the key can upload (every requested scope, or at least
 * createDataSet and addPieces), 2 when the wait timed out, `--no-wait`
 * skipped it, or the owner granted too few scopes (rerun resumes the same
 * key), 1 on an error.
 */

import * as Keysmith from '@filoz/keysmith'
import {
  AddPiecesPermission,
  CreateDataSetPermission,
  type Permission,
  PermissionNames,
} from '@filoz/synapse-core/session-key'
import type { FilecoinChain } from '@filoz/synapse-sdk'
import pc from 'picocolors'
import { type Address, createClient, createPublicClient, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { getBlockNumber } from 'viem/actions'
import { EXIT_CODE_INCOMPLETE } from '../common/cli-errors.js'
import {
  buildAuthorizeUrl,
  buildFundingUrl,
  buildSetupUrl,
  consoleNetworkSlug,
  DEFAULT_SUGGESTED_DEPOSIT_USDFC,
  keyAgreementMessage,
  resolveConsoleUrl,
} from '../core/session/console-url.js'
import { generateSessionKeypair } from '../core/session/create-session-key.js'
import {
  DEFAULT_WATCH_DEADLINE_MS,
  readScopeGrants,
  type WatchAuthorizationResult,
  watchAuthorization,
} from '../core/session/watch-authorization.js'
import { initializeSynapse } from '../core/synapse/index.js'
import { type GrantInbox, grantPort, grantReturnMode, openGrantInbox } from '../keyspace/grant-return.js'
import { acceptKeyspaceGrant, openSavedKeyspace, parseRole } from '../keyspace/keyspace.js'
import { resolveNetwork } from '../session/resolve-network.js'
import { parseScopes, SCOPE_IDS, SCOPE_PERMISSIONS } from '../session/scopes.js'
import { createSpinner } from '../utils/cli-helpers.js'
import { isTTY, log } from '../utils/cli-logger.js'
import { formatCountdown, formatExpiryDate, shortAddress } from './format.js'
import { openBrowser } from './open-browser.js'
import { checkAccountReadiness, formatReadinessLines } from './readiness.js'
import { getSessionFilePath, readSessionFile, type SavedSession, writeSessionFile } from './session-file.js'
import type { LoginOptions } from './types.js'

const DEFAULT_LOGIN_PERMISSIONS: Permission[] = [CreateDataSetPermission, AddPiecesPermission]

/** Scope id (camelCase, as used in `--scopes` and console URLs) for a permission. */
function scopeIdOf(permission: Permission): string {
  const id = SCOPE_IDS.find((candidate) => SCOPE_PERMISSIONS[candidate] === permission)
  return id ?? PermissionNames[permission] ?? permission
}

function scopeList(permissions: readonly Permission[]): string {
  return permissions.map(scopeIdOf).join(', ')
}

/** Credentials in the shell that would shadow the saved login for every later command. */
const SHADOWING_ENV_VARS = ['PRIVATE_KEY', 'SESSION_KEY', 'VIEW_ADDRESS'] as const

interface LoadedSession {
  session: SavedSession
  resumed: boolean
  /** A previously authorized key that `--fresh` is replacing; it stays live on chain. */
  replaced?: SavedSession
}

/**
 * Resume the saved key unless `--fresh`; otherwise generate and save a new
 * one for `network`. A saved key made for another network is refused: its
 * grant lives on that chain, so resuming it here could never succeed.
 */
function loadOrCreateSession(fresh: boolean | undefined, network: string, path: string): LoadedSession {
  const saved = readSessionFile(path)
  if (saved !== undefined && !fresh) {
    if (saved.network !== undefined && saved.network !== network) {
      throw new Error(
        `The saved login is for ${saved.network}, not ${network}. Pass --network ${saved.network} to resume it, or --fresh to replace it.`
      )
    }
    return { session: saved.network === undefined ? { ...saved, network } : saved, resumed: true }
  }
  const keypair = generateSessionKeypair()
  const session: SavedSession = { sessionKey: keypair.privateKey, sessionAddress: keypair.address, network }
  writeSessionFile(session, path)
  return saved?.walletAddress !== undefined ? { session, resumed: false, replaced: saved } : { session, resumed: false }
}

/**
 * Exit 0 only when every requested scope was granted. The caller asked for a
 * set; a scope the owner declined is a shortfall for whatever that caller
 * meant to run, so the exit code says so and the printed diff names it.
 */
function grantedEveryRequested(requested: readonly Permission[], granted: readonly Permission[]): boolean {
  const have = new Set(granted)
  return requested.every((p) => have.has(p))
}

/** Print the requested-versus-granted diff and the exit code for a shortfall. */
function reportPartialGrant(requested: readonly Permission[], result: WatchAuthorizationResult): void {
  const granted = new Set(result.granted)
  log.line(
    result.granted.length === 0
      ? `${pc.yellow('⚠')} Authorized with none of the requested scopes`
      : `${pc.yellow('⚠')} Authorized with fewer scopes than requested`
  )
  log.line(`  Requested:  ${scopeList(requested)}`)
  log.line(
    `  Granted:    ${requested
      .map((p) =>
        granted.has(p) ? `${scopeIdOf(p)} ${pc.green('✓')}` : `${scopeIdOf(p)} ${pc.red('✗')} (owner declined)`
      )
      .join('   ')}`
  )
  const canUpload = granted.has(CreateDataSetPermission) && granted.has(AddPiecesPermission)
  const missingIds = result.missing.map(scopeIdOf).join(', ')
  log.line(
    canUpload
      ? `  Uploads will work. Commands needing ${missingIds} will fail until the owner grants them.`
      : `  Commands needing ${missingIds} will fail until the owner grants them.`
  )
  log.line(`  Rerun \`filecoin-pin login\` to ask again, or \`login --scopes\` with only the scopes you need.`)
}

/** Print the readiness scorecard for `owner` and the funding link when something is missing. */
async function reportReadiness(
  owner: Address,
  chain: FilecoinChain,
  rpcUrl: string,
  consoleUrl: string
): Promise<void> {
  const synapse = await initializeSynapse({ walletAddress: owner, readOnly: true, chain, rpcUrl })
  const readiness = await checkAccountReadiness(synapse)
  log.line('')
  log.line('  Account readiness for uploads:')
  for (const line of formatReadinessLines(readiness, true)) log.line(line)
  if (!readiness.serviceApproved || readiness.depositUsdfc === 0n) {
    log.line('')
    log.line('  One step fixes both (deposit & approve is a single transaction):')
    log.line(buildFundingUrl(consoleUrl, DEFAULT_SUGGESTED_DEPOSIT_USDFC, chain.id))
  }
  log.line('')
  log.line(pc.gray('  check anytime: filecoin-pin balance · top up: filecoin-pin dashboard'))
}

/**
 * Run `login`. Returns the process exit code rather than calling
 * `process.exit`, so the command wrapper stays in charge of flushing. The
 * one exception is Ctrl-C during the wait: its handler stops the spinner
 * and exits 2 itself, because the process is going down either way.
 */
export async function runLogin(options: LoginOptions): Promise<number> {
  const permissions = options.scopes !== undefined ? parseScopes(options.scopes).permissions : DEFAULT_LOGIN_PERMISSIONS
  const { chain, transport, rpcUrl } = await resolveNetwork(options)
  const registryAddress = chain.contracts.sessionKeyRegistry?.address
  if (registryAddress === undefined) {
    throw new Error(`No session key registry is configured for chain id ${chain.id}`)
  }
  const network = consoleNetworkSlug(chain.id)
  if (network === undefined) {
    throw new Error(
      `The Filecoin Cloud console has no pairing page for chain id ${chain.id}. login works on mainnet and calibration; on other networks use \`filecoin-pin session create\` with the wallet key.`
    )
  }
  const consoleUrl = resolveConsoleUrl()
  const requestedKeyspace = parseKeyspaceOption(options.keyspace)
  const role = options.role === undefined ? undefined : parseRole(options.role)
  if (role !== undefined && requestedKeyspace === undefined) {
    throw new Error('--role shares one role of a keyspace: add --keyspace <id|new>.')
  }
  // Checked before a key is saved, so a misspelt setting leaves nothing behind.
  const grantReturn = requestedKeyspace === undefined ? undefined : { mode: grantReturnMode(), port: grantPort() }

  const path = getSessionFilePath()
  const { session, resumed, replaced } = loadOrCreateSession(options.fresh, network, path)
  const short = shortAddress(session.sessionAddress)
  log.line(`${pc.green('✓')} ${resumed ? 'Resuming session key' : 'Session key generated'}: ${short} (${network})`)
  log.line(`${pc.green('✓')} Saved to ${path} (owner-readable only, saved BEFORE the browser opens — safe to re-run)`)
  if (replaced !== undefined) {
    log.line(
      `${pc.yellow('⚠')} Replaced ${shortAddress(replaced.sessionAddress)}, which stays authorized on chain until it expires. Revoke it early on the console's Session keys page.`
    )
  }
  for (const name of SHADOWING_ENV_VARS) {
    if (process.env[name] !== undefined && process.env[name] !== '') {
      log.line(
        `${pc.yellow('⚠')} ${name} is set in this shell and takes precedence over the saved login. Unset it to use this session key.`
      )
    }
  }
  // Already holding what was asked for: nothing for the owner to sign, so the console is not opened.
  if (resumed && requestedKeyspace !== undefined) {
    const reuse = await savedKeyspaceCovers(session, requestedKeyspace, role, async (owner) => {
      const scopes = await readScopeGrants({
        client: createPublicClient({ chain, transport }),
        sessionAddress: session.sessionAddress,
        registryAddress,
        permissions,
        owner,
      })
      return scopes.status === 'granted'
    })
    if (reuse.ok) {
      log.line(
        `${pc.green('✓')} Already authorized, and keyspace ${reuse.keyspace}${role ? `, role ${role},` : ''} is shared with this key until ${formatExpiryDate(BigInt(reuse.expires))}. Nothing to sign.`
      )
      log.line('  Use --fresh for a new session key and a new keyspace grant.')
      log.flush()
      return 0
    }
    if (reuse.reason) log.line(`  The saved keyspace grant can't be reused: ${reuse.reason}. Asking the console again.`)
  }

  const scopeNote = options.scopes === undefined ? ' (defaults — override with --scopes)' : ''
  log.line(`  Requesting scopes: ${scopeList(permissions)}${scopeNote}`)
  log.line('')

  const scopeIds = permissions.map(scopeIdOf)
  // Opened before the link is printed, so a keyspace grant the console sends early is kept.
  let inbox: GrantInbox | undefined
  if (grantReturn !== undefined) {
    inbox = await openGrantInbox({
      mode: grantReturn.mode,
      consoleOrigin: new URL(consoleUrl).origin,
      port: grantReturn.port,
      interactive: isTTY() && process.stdin.isTTY === true,
    })
    log.line(
      `  Requesting keyspace: ${requestedKeyspace}${role ? `, role ${role}` : ''}${inbox.callback ? ` (the console sends it back to ${inbox.callback.replace(/\/[0-9a-f]+$/, '/…')})` : ' (you paste the code the console shows)'}`
    )
  }
  const agreementKey = requestedKeyspace === undefined ? undefined : Keysmith.publicKeyOf(session.sessionKey)
  const url =
    requestedKeyspace === undefined || agreementKey === undefined
      ? buildAuthorizeUrl(consoleUrl, session.sessionAddress, scopeIds, chain.id)
      : buildSetupUrl(consoleUrl, session.sessionAddress, scopeIds, chain.id, {
          publicKey: agreementKey,
          signature: await privateKeyToAccount(session.sessionKey).signMessage({
            message: keyAgreementMessage(agreementKey),
          }),
          keyspace: requestedKeyspace,
          role,
          callback: inbox?.callback,
        })
  log.line('  Approve this key with your wallet in the Filecoin Cloud console:')
  // The link on its own line, unstyled, so it copies and parses cleanly.
  log.line(url)
  log.line('')
  log.flush()
  if (options.browser !== false) openBrowser(url)

  // The link is already on screen: an RPC that is down here costs the wait, not the pairing.
  const client = createPublicClient({ chain, transport })

  if (options.wait === false) {
    // This exit tells the owner to rerun `login`, and the grant is usually
    // mined before they do, so it needs the same resume marker the wait
    // records. Best effort: the pairing is done and an RPC that is down here
    // must not undo it; a rerun without a marker starts at its own head.
    if (session.fromBlock === undefined) {
      try {
        writeSessionFile({ ...session, fromBlock: await getBlockNumber(client) }, path)
      } catch {
        // A rerun will start at its own head; the pairing still stands.
      }
    }
    log.line(
      `${pc.yellow('⚠')} Not waiting for the grant. Approve the key, then rerun \`filecoin-pin login\` to check it.`
    )
    if (inbox) {
      inbox.close()
      log.line('  Save the keyspace grant code the console shows with `filecoin-pin keyspace import <code>`.')
    }
    log.flush()
    return EXIT_CODE_INCOMPLETE
  }

  // A resumed wait scans from where the first one started, so a grant that
  // landed while nothing was watching is still found. The owner authorizes
  // once; a rerun that scanned from the current block would wait for a second
  // event that never comes.
  const fromBlock = session.fromBlock ?? (await getBlockNumber(client))
  if (session.fromBlock === undefined) writeSessionFile({ ...session, fromBlock }, path)
  const deadlineMs = options.timeout !== undefined ? options.timeout * 1000 : DEFAULT_WATCH_DEADLINE_MS
  const spinner = createSpinner()
  const waitLine = (remainingMs: number) =>
    `Waiting for on-chain authorization… ${formatCountdown(remainingMs)} remaining (Ctrl-C safe; rerun \`login\` to resume)`
  // Registered before the spinner starts: clack installs its own SIGINT
  // handler in start(), and the first listener to call process.exit wins.
  const onSigint = () => {
    spinner.stop(`${pc.yellow('⚠')} Login paused. Your key is saved; rerun \`filecoin-pin login\` to resume.`)
    log.flush()
    process.exit(EXIT_CODE_INCOMPLETE)
  }
  process.once('SIGINT', onSigint)
  if (!isTTY()) log.line(`  ${waitLine(deadlineMs)}`)
  spinner.start(waitLine(deadlineMs))
  let result: WatchAuthorizationResult
  try {
    result = await watchAuthorization({
      client,
      sessionAddress: session.sessionAddress,
      registryAddress,
      permissions,
      fromBlock,
      deadlineMs,
      ...(session.walletAddress !== undefined ? { owner: session.walletAddress } : {}),
      onProgress: (event) => {
        if (event.type === 'watch:tick') spinner.message(waitLine(event.data.remainingMs))
      },
    })
  } catch (error) {
    spinner.stop(
      `${pc.red('✗')} Could not watch for the authorization. Your key is saved; rerun \`filecoin-pin login\` to resume.`
    )
    throw error
  } finally {
    process.off('SIGINT', onSigint)
  }

  if (result.status === 'timeout' || result.owner === undefined) {
    inbox?.close()
    spinner.stop(
      `${pc.yellow('⚠')} No authorization seen in time. Your key is saved; rerun \`filecoin-pin login\` to resume.`
    )
    log.flush()
    return EXIT_CODE_INCOMPLETE
  }

  writeSessionFile({ ...session, fromBlock, walletAddress: result.owner }, path)
  const expires = result.expiry !== undefined ? ` · expires ${formatExpiryDate(result.expiry)}` : ''
  if (result.status === 'granted') {
    spinner.stop(`${pc.green('✓')} Authorized! Granted: ${scopeList(result.granted)}${expires}`)
  } else {
    spinner.stop('')
    reportPartialGrant(permissions, result)
  }

  let keyspaceShared = true
  if (inbox && requestedKeyspace !== undefined) {
    keyspaceShared = await receiveKeyspace(inbox, {
      session: { ...session, fromBlock, walletAddress: result.owner },
      requested: requestedKeyspace,
      role,
      client: createClient({ chain, transport }),
      deadline: Date.now() + deadlineMs,
      path,
    })
  }

  // Funding never blocks login: a failed readiness read is reported, not fatal.
  try {
    await reportReadiness(result.owner, chain, rpcUrl, consoleUrl)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    log.line(`${pc.yellow('⚠')} Could not read account readiness: ${reason}. Run \`filecoin-pin balance\` to check.`)
  }
  log.flush()
  return grantedEveryRequested(permissions, result.granted) && keyspaceShared ? 0 : EXIT_CODE_INCOMPLETE
}

/** `--keyspace`: `new`, or a 16-byte keyspace id. */
/**
 * Whether the keyspace grant saved with this login already covers the keyspace
 * and role asked for, and the session key still holds every requested scope.
 * Decided from session.env and the chain alone: the console is never asked.
 * `reason` is set only when a saved grant exists but does not fit.
 */
async function savedKeyspaceCovers(
  session: SavedSession,
  requested: Hex | 'new',
  role: string | undefined,
  scopesLive: (owner: Address) => Promise<boolean>
): Promise<{ ok: true; keyspace: Hex; expires: number } | { ok: false; reason?: string }> {
  if (session.keyspaceGrant === undefined || session.walletAddress === undefined) return { ok: false }
  if (requested === 'new') return { ok: false, reason: '--keyspace new asks for another keyspace' }
  let open: Awaited<ReturnType<typeof openSavedKeyspace>>
  try {
    open = await openSavedKeyspace(session)
  } catch (error) {
    const cause = error instanceof Error && error.cause instanceof Error ? error.cause : error
    return { ok: false, reason: cause instanceof Error ? cause.message : String(cause) }
  }
  if (open.chain.owner.toLowerCase() !== session.walletAddress.toLowerCase()) {
    return { ok: false, reason: `it is from ${open.chain.owner}, not ${session.walletAddress}` }
  }
  if (open.keyspace !== requested) return { ok: false, reason: `it is for keyspace ${open.keyspace}` }
  if (open.role !== role)
    return { ok: false, reason: `it is for ${open.role ? `role ${open.role}` : 'the whole keyspace'}` }
  if (!(await scopesLive(session.walletAddress))) {
    return { ok: false, reason: 'the session key no longer holds every requested scope' }
  }
  return { ok: true, keyspace: open.keyspace, expires: open.expires }
}

function parseKeyspaceOption(value: string | undefined): Hex | 'new' | undefined {
  if (value === undefined) return undefined
  const keyspace = value.trim().toLowerCase()
  if (keyspace === 'new' || /^0x[0-9a-f]{32}$/.test(keyspace)) return keyspace as Hex | 'new'
  throw new Error(`--keyspace takes a keyspace id (0x and 32 hex digits) or new, not "${value}".`)
}

/**
 * Wait for the keyspace grant from the console, check it against this login
 * and the chain, and save it with the session key. Returns whether it was saved.
 */
async function receiveKeyspace(
  inbox: GrantInbox,
  options: {
    session: SavedSession & { walletAddress: Address }
    requested: Hex | 'new'
    role: string | undefined
    client: Parameters<typeof acceptKeyspaceGrant>[0]['client']
    deadline: number
    path: string
  }
): Promise<boolean> {
  const { session, requested, role, client, deadline, path } = options
  log.line(
    `  Now share the keyspace in the console (step "Share an encryption keyspace").${inbox.callback ? ' It comes back here by itself.' : ''}`
  )
  log.flush()
  try {
    const code = await Promise.race([
      inbox.receive('  Paste the keyspace grant code from the console (or wait for it to arrive): '),
      // Does not hold the process open, unlike a timer left running.
      new Promise<undefined>((resolve) => {
        AbortSignal.timeout(Math.max(0, deadline - Date.now())).addEventListener('abort', () => resolve(undefined))
      }),
    ])
    if (code === undefined) {
      log.line(
        `${pc.yellow('⚠')} No keyspace grant arrived in time. Save the code the console shows with \`filecoin-pin keyspace import <code>\`.`
      )
      return false
    }
    const opened = await acceptKeyspaceGrant({
      code,
      sessionKey: session.sessionKey,
      owner: session.walletAddress,
      requested,
      role,
      client,
    })
    writeSessionFile({ ...session, keyspace: opened.keyspace, keyspaceGrant: code.trim() }, path)
    log.line(
      `${pc.green('✓')} Keyspace ${opened.keyspace}${opened.role ? `, role ${opened.role},` : ''} shared until ${formatExpiryDate(BigInt(opened.expires))}: its key matches what your wallet signed${opened.checkedOnChain ? ', and the keyspace matches its on-chain commitment' : ' (a new keyspace: the first upload records its commitment)'}`
    )
    log.line(`  Saved with the session key. Try: filecoin-pin keyspace put <file>`)
    return true
  } catch (error) {
    log.line(`${pc.red('✗')} ${error instanceof Error ? error.message : String(error)}`)
    return false
  } finally {
    inbox.close()
    log.flush()
  }
}

/**
 * Action handlers for `filecoin-pin keyspace put|get|ls|import`: encrypted
 * storage in the Keysmith keyspace the owner shared with this login.
 */

import { readFileSync, writeFileSync } from 'node:fs'
import * as Keysmith from '@filoz/keysmith'
import { CID } from 'multiformats/cid'
import pc from 'picocolors'
import { createClient } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { initializeSynapse } from '../core/synapse/index.js'
import { formatExpiryDate } from '../login/format.js'
import { getSessionFilePath, readSessionFile, type SavedSession, writeSessionFile } from '../login/session-file.js'
import { resolveNetwork } from '../session/resolve-network.js'
import { log } from '../utils/cli-logger.js'
import {
  acceptKeyspaceGrant,
  assertCanAddPieces,
  decryptPiece,
  encryptPiece,
  keyspacePieces,
  openSavedKeyspace,
  parseRole,
  sessionKeySynapse,
  storePiece,
  toCode,
} from './keyspace.js'

/** The saved login, which must be authorized: keyspace commands sign and read as its owner. */
function authorizedSession(): SavedSession & { walletAddress: `0x${string}` } {
  const session = readSessionFile()
  if (session?.walletAddress === undefined) {
    throw new Error('Not logged in. Run `filecoin-pin login --keyspace <id|new>` first.')
  }
  return session as SavedSession & { walletAddress: `0x${string}` }
}

async function connect(session: SavedSession & { walletAddress: `0x${string}` }) {
  const { chain, transport, rpcUrl } = await resolveNetwork({ network: session.network })
  // Reads carry no account: Lotus refuses calls from an address it has never seen.
  const client = createClient({ chain, transport })
  return { chain, rpcUrl, client }
}

export async function runKeyspacePut(file: string): Promise<void> {
  const session = authorizedSession()
  const open = await openSavedKeyspace(session)
  const { chain, rpcUrl, client } = await connect(session)
  await assertCanAddPieces(client, session.walletAddress, session.sessionAddress)

  const plaintext = new Uint8Array(readFileSync(file))
  const envelope = await encryptPiece(open, plaintext)
  log.line(
    `${pc.green('✓')} Encrypted ${file}: ${plaintext.length} B → ${envelope.length} B envelope, keyspace ${open.keyspace}${open.role ? `, role ${open.role}` : ''}`
  )
  log.flush()

  const synapse = sessionKeySynapse({ chain, rpcUrl, owner: session.walletAddress, sessionKey: session.sessionKey })
  // The claim's root carries the keyspace commitment, so even a role can write a new keyspace's first datasets.
  const metadata = { [Keysmith.KEYSPACE_ID_KEY]: open.keyspace, [Keysmith.COMMITMENT_KEY]: open.commitment }
  const { pieceCid, copies } = await storePiece(synapse, client, envelope, metadata, (event) =>
    console.log(pc.gray(`  ${event}`))
  )
  log.line(`${pc.green('✓')} Stored, ${copies} cop${copies === 1 ? 'y' : 'ies'}, confirmed on chain`)
  log.line(pieceCid)
  log.flush()
}

export async function runKeyspaceGet(pieceCid: string, output: string | undefined): Promise<void> {
  const session = authorizedSession()
  const open = await openSavedKeyspace(session)
  const { chain, rpcUrl } = await connect(session)
  const synapse = await initializeSynapse({ walletAddress: session.walletAddress, readOnly: true, chain, rpcUrl })
  const envelope = await synapse.storage.download({ pieceCid })
  const plaintext = await decryptPiece(open, envelope)
  if (output === undefined) {
    process.stdout.write(plaintext)
    if (process.stdout.isTTY) process.stdout.write('\n')
  } else {
    writeFileSync(output, plaintext)
    console.error(`${pc.green('✓')} Decrypted ${pieceCid} to ${output} (${plaintext.length} B)`)
  }
}

export async function runKeyspaceLs(): Promise<void> {
  const session = authorizedSession()
  const open = await openSavedKeyspace(session)
  const { client } = await connect(session)
  const pieces = await keyspacePieces(client, session.walletAddress, open.keyspace)
  log.line(
    `Keyspace ${open.keyspace} of ${session.walletAddress}${open.role ? ` (this login holds role ${open.role})` : ''}: ${pieces.length} piece(s)`
  )
  for (const { pieceCid, dataSetIds } of pieces)
    log.line(`  ${pieceCid}  ${pc.gray(`datasets ${dataSetIds.join(', ')}`)}`)
  log.flush()
}

export async function runKeyspaceImport(
  code: string,
  requested: string | undefined,
  role: string | undefined
): Promise<void> {
  const session = authorizedSession()
  const { client } = await connect(session)
  const opened = await acceptKeyspaceGrant({
    code,
    sessionKey: session.sessionKey,
    owner: session.walletAddress,
    requested: (requested ?? 'new') as `0x${string}` | 'new',
    role: role === undefined ? undefined : parseRole(role),
    client,
  })
  writeSessionFile({ ...session, keyspace: opened.keyspace, keyspaceGrant: code.trim() }, getSessionFilePath())
  log.line(
    `${pc.green('✓')} Keyspace ${opened.keyspace}${opened.role ? `, role ${opened.role},` : ''} shared with this login until ${formatExpiryDate(BigInt(opened.expires))}: its key matches what your wallet signed${opened.checkedOnChain ? ', and the keyspace matches its on-chain commitment' : ''}`
  )
  log.flush()
}

/** Print the `Authorization` header a gating provider checks: the claim chain and a request for one piece, signed by this session key. */
export async function runKeyspaceHeader(pieceCid: string): Promise<void> {
  const session = authorizedSession()
  const open = await openSavedKeyspace(session)
  const request = await Keysmith.signRequest(privateKeyToAccount(session.sessionKey), open.chain, {
    pieceCid: CID.parse(pieceCid).bytes,
    expires: Math.floor(Date.now() / 1000) + Keysmith.MAX_REQUEST_LIFETIME,
  })
  console.log(`Authorization: FOC-Grant ${toCode(Keysmith.encodePresentation(open.chain, request))}`)
}

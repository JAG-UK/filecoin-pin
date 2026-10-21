/**
 * A Keysmith keyspace shared with this session key: check a keyspace grant
 * before saving it, open the saved one, and encrypt, store, list and read
 * pieces in the keyspace through Synapse.
 *
 * Synapse never sees a key. Pieces go up as FEE envelopes with the keyspace
 * and its commitment as dataset metadata, so Synapse adds them to the owner's
 * datasets for that keyspace (or makes them, the first time).
 */

import * as Keysmith from '@filoz/keysmith'
import { getActivePiecesByCursor } from '@filoz/synapse-core/pdp-verifier'
import { AddPiecesPermission, authorizationExpiry, fromSecp256k1 } from '@filoz/synapse-core/session-key'
import { getAllDataSetMetadata, getClientDataSets } from '@filoz/synapse-core/warm-storage'
import { type FilecoinChain, Synapse } from '@filoz/synapse-sdk'
import * as fee from 'filecoin-encryption-envelope'
import {
  type Address,
  type Chain,
  type Client,
  custom,
  getAddress,
  type Hex,
  type HttpTransport,
  publicActions,
  type Transport,
} from 'viem'
import { APPLICATION_SOURCE } from '../core/synapse/constants.js'
import { createTransport } from '../core/synapse/create-transport.js'

type Reader = Client<Transport, Chain>

export const toCode = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
const fromCode = (code: string) => new Uint8Array(Buffer.from(code.trim(), 'base64url'))

/** A keyspace shared with this login: the owner's claim chain, the key it carries, and what it covers. */
export interface OpenKeyspace {
  keyspace: Hex
  grant: Keysmith.Grant
  /** The claim chain, its root signed by the owner's wallet. */
  chain: Keysmith.ClaimChain
  /** The keyspace key, or a role's key: a role opens only what is stored under it. */
  key: Uint8Array
  /** The role the claim covers (a Keysmith scope path); undefined for the whole keyspace. */
  role: string | undefined
  /** `foc/kc`, from the claim's root, which the owner's wallet signed. */
  commitment: string
  /** Unix seconds: the claim ends with the session key, and providers stop serving this login then. */
  expires: number
}

/** The role a claim's node covers, undefined for the whole keyspace. A piece claim cannot be used here. */
function roleOf(node: string): string | undefined {
  if (node === 'keyspace') return undefined
  if (node.startsWith('scope:')) return node.slice('scope:'.length)
  throw new Error('That grant opens a single piece; it cannot be used to store or read a keyspace.')
}

/** `--role`, in Keysmith's canonical form. */
export function parseRole(value: string): string {
  try {
    return Keysmith.scopePath(value)
  } catch {
    throw new Error(`A role is one or more names separated by "/", such as team/alice, not "${value}".`)
  }
}

const commitmentText = (bytes: Hex) => `v1.${bytes.slice(2)}`

/** Every dataset the owner pays for that records the keyspace, with what it records as its commitment. */
export async function keyspaceDataSets(
  client: Reader,
  owner: Address,
  keyspace: Hex
): Promise<{ id: bigint; commitment: string | undefined }[]> {
  const { items } = await getClientDataSets(client, { address: owner })
  const found: { id: bigint; commitment: string | undefined }[] = []
  for (const { dataSetId } of items) {
    const metadata = await getAllDataSetMetadata(client, { dataSetId: BigInt(dataSetId) })
    if (metadata[Keysmith.KEYSPACE_ID_KEY]?.toLowerCase() === keyspace.toLowerCase()) {
      found.push({ id: BigInt(dataSetId), commitment: metadata[Keysmith.COMMITMENT_KEY] })
    }
  }
  return found
}

/**
 * Check a delivery from the console and open it: the claim's root signed by
 * the owner's wallet and unexpired (which also checks the key against the
 * commitment the owner signed), for the owner and the keyspace and role asked
 * for, and its keyspace commitment against the chain when the keyspace already
 * has datasets. Throws with the reason when any check fails; nothing is saved then.
 */
export async function acceptKeyspaceGrant(options: {
  code: string
  sessionKey: Hex
  owner: Address
  requested: Hex | 'new'
  /** The role asked for, in canonical form; undefined for the whole keyspace. */
  role?: string | undefined
  client: Reader
}): Promise<OpenKeyspace & { checkedOnChain: boolean }> {
  const { code, sessionKey, owner, requested, role, client } = options
  let opened: Awaited<ReturnType<typeof Keysmith.openDelivery>>
  try {
    opened = await Keysmith.openDelivery(sessionKey, fromCode(code))
  } catch (error) {
    throw new Error(`That keyspace grant was refused: ${error instanceof Error ? error.message : String(error)}`)
  }
  const { claim, key, grant, chain } = opened
  if (getAddress(claim.owner) !== getAddress(owner)) {
    throw new Error(
      `That keyspace grant is from ${claim.owner}, not ${owner}, the wallet that authorized this session key.`
    )
  }
  if (requested !== 'new' && claim.keyspace !== requested.toLowerCase()) {
    throw new Error(`That keyspace grant is for keyspace ${claim.keyspace}, not ${requested}.`)
  }
  const granted = roleOf(claim.node)
  if (granted !== role) {
    const describe = (r: string | undefined) => (r === undefined ? 'the whole keyspace' : `role ${r}`)
    throw new Error(`That grant is for ${describe(granted)}, not ${describe(role)}.`)
  }
  const commitment = commitmentText(claim.keyspaceCommitment)
  const recorded = (await keyspaceDataSets(client, owner, claim.keyspace)).find((each) => each.commitment)?.commitment
  if (recorded !== undefined && recorded !== commitment) {
    throw new Error(
      `That keyspace grant commits to another keyspace key than keyspace ${claim.keyspace} records on chain.`
    )
  }
  if (recorded === undefined && requested !== 'new') {
    throw new Error(`No dataset of ${owner} records keyspace ${claim.keyspace}.`)
  }
  return {
    keyspace: claim.keyspace,
    grant,
    chain,
    key,
    role: granted,
    commitment,
    expires: chain.expires,
    checkedOnChain: recorded !== undefined,
  }
}

/** Open the delivery saved with the login, offline: everything it needs is in the delivery. */
export async function openSavedKeyspace(session: {
  sessionKey: Hex
  keyspace?: Hex | undefined
  keyspaceGrant?: string | undefined
}): Promise<OpenKeyspace> {
  if (session.keyspace === undefined || session.keyspaceGrant === undefined) {
    throw new Error(
      'No keyspace is shared with this login. Run `filecoin-pin login --keyspace <id|new>`, or `filecoin-pin keyspace import <code>`.'
    )
  }
  let opened: Awaited<ReturnType<typeof Keysmith.openDelivery>>
  try {
    opened = await Keysmith.openDelivery(session.sessionKey, fromCode(session.keyspaceGrant))
  } catch (error) {
    throw new Error(
      `The saved keyspace grant no longer opens: ${error instanceof Error ? error.message : String(error)}. Run \`filecoin-pin login --keyspace\` again.`,
      { cause: error }
    )
  }
  const { chain, grant, key, claim } = opened
  return {
    keyspace: chain.keyspace,
    grant,
    chain,
    key,
    role: roleOf(claim.node),
    commitment: commitmentText(chain.keyspaceCommitment),
    expires: chain.expires,
  }
}

/** Encrypt under the grant's key (labelled with its role, if any): a fresh salt per piece, Keysmith's labels in the envelope. */
export async function encryptPiece(open: OpenKeyspace, plaintext: Uint8Array): Promise<Uint8Array> {
  const target = Keysmith.writeTarget(open.grant, open.key)
  const salt = Keysmith.newSalt()
  const appMetadata = Keysmith.pieceMetadata(target.ref, { salt, ...(target.scope ? { scope: target.scope } : {}) })
  const cek = Keysmith.pieceKey(target.key, salt)
  return collect(
    new Blob([new Uint8Array(plaintext)])
      .stream()
      .pipeThrough(fee.encrypt({ cek, appMetadata, contentLength: plaintext.length }))
  )
}

/** Decrypt a piece: FEE reads the envelope's labels, Keysmith derives the key or refuses. */
export async function decryptPiece(open: OpenKeyspace, envelope: Uint8Array): Promise<Uint8Array> {
  try {
    return await collect(
      new Blob([new Uint8Array(envelope)])
        .stream()
        .pipeThrough(fee.decrypt(Keysmith.keyResolver(open.key, Keysmith.holdingOf(open.grant))))
    )
  } catch (error) {
    // FEE reports "Key resolution failed"; Keysmith's reason, such as a piece outside this role, is its cause.
    const reason = error instanceof Error && error.cause instanceof Error ? error.cause.message : undefined
    throw new Error(reason ? `This login cannot open that piece: ${reason}` : String((error as Error).message ?? error))
  }
}

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  for await (const chunk of stream) chunks.push(chunk)
  return new Uint8Array(Buffer.concat(chunks))
}

/**
 * Lotus refuses calls from an address it has never seen, so Synapse's own
 * check, which reads as the session key, sees a fresh key as unauthorized.
 * This reads the registry with no account instead.
 */
export async function assertCanAddPieces(client: Reader, owner: Address, sessionAddress: Address): Promise<void> {
  const expiry = await authorizationExpiry(client, {
    address: owner,
    sessionKeyAddress: sessionAddress,
    permission: AddPiecesPermission,
  })
  if (expiry <= BigInt(Math.floor(Date.now() / 1000))) {
    throw new Error(
      `Session key ${sessionAddress} may not add pieces for ${owner}: it is ${expiry === 0n ? 'not authorized, or was revoked' : 'expired'}. Run \`filecoin-pin login\`.`
    )
  }
}

/**
 * Synapse signing as the session key, for the owner. Its reads carry no
 * `from`: Lotus refuses calls from an address it has never seen, and a
 * session key never sends a transaction of its own, so it is never seen.
 * Synapse reads as the session key when it creates a dataset (the first write
 * to a keyspace), and those reads are view calls that ignore the caller.
 * The command checks the key's authorization itself, so Synapse is asked for none.
 */
export function sessionKeySynapse(options: {
  chain: FilecoinChain
  rpcUrl: string
  owner: Address
  sessionKey: Hex
}): Synapse {
  const { chain, rpcUrl, owner, sessionKey } = options
  const node = createTransport(rpcUrl)({ chain, retryCount: 0 })
  const transport = custom({
    request: ({ method, params }: { method: string; params?: unknown[] }) => {
      if (method === 'eth_call' && Array.isArray(params) && params[0] && typeof params[0] === 'object') {
        const { from: _from, ...call } = params[0] as Record<string, unknown>
        return node.request({ method, params: [call, ...params.slice(1)] } as never)
      }
      return node.request({ method, params } as never)
    },
  })
  return Synapse.create({
    chain,
    transport,
    account: owner,
    // The SDK's types list only http, websocket and fallback transports; any viem transport works.
    sessionKey: fromSecp256k1({
      privateKey: sessionKey,
      root: owner,
      chain,
      transport: transport as unknown as HttpTransport,
    }),
    requiredPermissions: [],
    source: APPLICATION_SOURCE,
  })
}

/**
 * `synapse.storage.upload()`, confirmed by the chain. Curio batches piece
 * additions, and its status endpoint can answer 404 or "not yet" for minutes
 * after the transaction lands, which is what Synapse waits on. Once Synapse
 * has submitted the add-pieces transactions, their receipts decide.
 */
export async function storePiece(
  synapse: Synapse,
  client: Reader,
  bytes: Uint8Array,
  metadata: Record<string, string>,
  on?: (event: string) => void
): Promise<{ pieceCid: string; copies: number }> {
  let pieceCid = ''
  let copies = 1
  const submitted: Hex[] = []
  return new Promise((resolve, reject) => {
    let confirming = false
    const onSubmitted = (txHash: Hex, providerId: bigint) => {
      submitted.push(txHash)
      on?.(`provider ${providerId} submitted ${txHash}`)
      // Every copy is pulled before any commit starts, so the first submission knows how many follow.
      if (submitted.length < copies || confirming) return
      confirming = true
      const reader = client.extend(publicActions)
      // No replacement check: it fetches blocks by number, and Filecoin's null rounds have none.
      Promise.all(submitted.map((hash) => reader.waitForTransactionReceipt({ hash, checkReplacement: false })))
        .then((receipts) => {
          const reverted = receipts.find((receipt) => receipt.status !== 'success')
          if (reverted) throw new Error(`Add-pieces transaction ${reverted.transactionHash} reverted`)
          resolve({ pieceCid, copies })
        })
        .catch(reject)
    }
    synapse.storage
      .upload(bytes, {
        metadata,
        callbacks: {
          onStored: (providerId, cid) => {
            pieceCid = cid.toString()
            on?.(`provider ${providerId} stored ${pieceCid}`)
          },
          onCopyComplete: (providerId) => {
            copies++
            on?.(`provider ${providerId} pulled a copy`)
          },
          onPiecesAdded: (txHash, providerId) => onSubmitted(txHash, providerId),
        },
      })
      .then((result) => resolve({ pieceCid: result.pieceCid.toString(), copies: result.copies.length }))
      // Once submitted, the receipts decide; Synapse failing only its status wait is not a failure.
      .catch((error) => submitted.length === 0 && reject(error))
  })
}

/** Every live piece in the keyspace's datasets, once per piece CID. */
export async function keyspacePieces(
  client: Reader,
  owner: Address,
  keyspace: Hex
): Promise<{ pieceCid: string; dataSetIds: bigint[] }[]> {
  const pieces = new Map<string, bigint[]>()
  for (const { id } of await keyspaceDataSets(client, owner, keyspace)) {
    let cursor: bigint | undefined
    do {
      const page = await getActivePiecesByCursor(client, { dataSetId: id, ...(cursor !== undefined ? { cursor } : {}) })
      for (const { cid } of page.items) pieces.set(cid.toString(), [...(pieces.get(cid.toString()) ?? []), id])
      cursor = page.nextCursor
    } while (cursor !== undefined)
  }
  return [...pieces].map(([pieceCid, dataSetIds]) => ({ pieceCid, dataSetIds }))
}

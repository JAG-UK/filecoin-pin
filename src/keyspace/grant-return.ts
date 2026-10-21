/**
 * How a keyspace grant gets from the console back to this process.
 *
 * - loopback: a listener on 127.0.0.1 that the console page posts the grant
 *   to. Its path is a random nonce, so no other local page or process can post
 *   a grant of its own. It answers with CORS for the console's origin, so the
 *   page can say the grant arrived.
 * - paste: the console shows the grant as a code and the owner pastes it here.
 *
 * `KEYSPACE_GRANT_RETURN` picks `both` (the default: whichever arrives first),
 * `loopback` or `paste`. `KEYSPACE_GRANT_PORT` fixes the listener's port (default:
 * any free one), for example to forward it over SSH with `ssh -L`.
 *
 * Neither channel needs to keep the grant secret: it is encrypted to the
 * session key. Both keep it on the owner's machine, so a setup link someone
 * else wrote never delivers a grant to them.
 */

import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { createServer, type IncomingMessage, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { createInterface } from 'node:readline'

export type GrantReturn = 'both' | 'loopback' | 'paste'

/** `KEYSPACE_GRANT_RETURN`, checked: a misspelt value is an error, not a silent default. */
export function grantReturnMode(env: NodeJS.ProcessEnv = process.env): GrantReturn {
  const raw = env.KEYSPACE_GRANT_RETURN
  const value = (raw ?? 'both').trim().toLowerCase()
  if (value === 'both' || value === 'loopback' || value === 'paste') return value
  throw new Error(`KEYSPACE_GRANT_RETURN must be both, loopback or paste, not "${raw}".`)
}

/** `KEYSPACE_GRANT_PORT`, or 0 for any free port. */
export function grantPort(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.KEYSPACE_GRANT_PORT
  if (raw === undefined || raw.trim() === '') return 0
  const port = Number(raw)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`KEYSPACE_GRANT_PORT must be a port number, not "${raw}".`)
  }
  return port
}

/** A grant code is base64url CBOR, a couple of hundred characters. Anything much longer is not one. */
const MAX_CODE_LENGTH = 4096

export interface GrantInbox {
  /** The loopback URL for the console link; undefined when only a paste is taken. */
  callback: string | undefined
  /** Wait for a grant code from whichever channels the mode allows. */
  receive(prompt: string): Promise<string>
  close(): void
}

/**
 * Open the channels `mode` allows. The listener starts now, before the link is
 * printed, so a grant posted while the CLI is still waiting for the on-chain
 * authorization is kept until `receive` is called.
 */
export async function openGrantInbox(options: {
  mode: GrantReturn
  consoleOrigin: string
  port?: number
  interactive: boolean
}): Promise<GrantInbox> {
  const { mode, consoleOrigin, interactive } = options
  if (mode === 'paste' && !interactive) {
    throw new Error(
      'KEYSPACE_GRANT_RETURN=paste needs a terminal to paste into. Use loopback, or add the grant later with `filecoin-pin keyspace import <code>`.'
    )
  }

  let server: Server | undefined
  let callback: string | undefined
  // Never settles when there is no listener, so a paste always wins the race then.
  let deliver: ((code: string) => void) | undefined
  const posted = new Promise<string>((resolve) => {
    deliver = resolve
  })
  if (mode !== 'paste') {
    const nonce = randomBytes(16).toString('hex')
    const cors = {
      'access-control-allow-origin': consoleOrigin,
      'access-control-allow-methods': 'POST',
      'access-control-allow-headers': 'content-type',
      // Chrome's local network access checks ask a local server to opt in to requests from public sites.
      'access-control-allow-private-network': 'true',
      vary: 'origin',
    }
    server = createServer((request, response) => {
      if (request.url !== `/${nonce}`) return void response.writeHead(404, cors).end()
      if (request.method === 'OPTIONS') return void response.writeHead(204, cors).end()
      if (request.method !== 'POST') return void response.writeHead(405, cors).end()
      readBody(request)
        .then((code) => {
          response.writeHead(200, { ...cors, 'content-type': 'text/plain' }).end('received')
          deliver?.(code)
        })
        .catch(() => response.writeHead(413, cors).end())
    })
    server.listen(options.port ?? 0, '127.0.0.1')
    await once(server, 'listening')
    callback = `http://127.0.0.1:${(server.address() as AddressInfo).port}/${nonce}`
  }

  return {
    callback,
    async receive(prompt) {
      if (mode === 'loopback' || !interactive) return posted
      const readline = createInterface({ input: process.stdin, output: process.stdout })
      try {
        const pasted = new Promise<string>((resolve) => {
          const ask = () =>
            readline.question(prompt, (line) => {
              const code = line.trim()
              if (code === '') ask()
              else resolve(code)
            })
          ask()
        })
        return await Promise.race([posted, pasted])
      } finally {
        readline.close()
      }
    },
    close() {
      server?.close()
    },
  }
}

async function readBody(request: IncomingMessage): Promise<string> {
  let body = ''
  for await (const chunk of request) {
    body += String(chunk)
    if (body.length > MAX_CODE_LENGTH) throw new Error('too long')
  }
  return body.trim()
}

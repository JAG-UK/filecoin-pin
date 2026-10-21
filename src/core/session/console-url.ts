/**
 * Console URL helpers: the canonical builder for Filecoin Cloud console
 * deep links. Session-key pairing/login work builds on these same helpers.
 */

import { telemetryConfig } from '../telemetry/index.js'

/**
 * One console deployment serves both networks and switches network in-app,
 * so the network travels in the `network` query parameter rather than in
 * the base URL. `CONSOLE_URL` overrides for local or preview consoles.
 */
export const DEFAULT_CONSOLE_URL = 'https://pay.filecoin.cloud'

/** Console base URL: `CONSOLE_URL` when set, otherwise the production deployment. */
export function resolveConsoleUrl(): string {
  return process.env.CONSOLE_URL ?? DEFAULT_CONSOLE_URL
}

/**
 * Append `utm_source/medium/term[/content]` so the console's analytics
 * can attribute the visit (affordance, flow, human vs which agent). Returns
 * `url` unchanged when telemetry is disabled. `utm_campaign` is left for
 * marketing campaign names.
 */
function withUtm(url: string, flow: 'login' | 'fund' | 'revoke' | 'dashboard'): string {
  const { disabled, affordance, driver } = telemetryConfig()
  if (disabled) return url
  const medium = affordance.toLowerCase().replace(/ /g, '-')
  const content = driver === undefined ? '' : `&utm_content=${encodeURIComponent(driver)}`
  return `${url}${url.includes('?') ? '&' : '?'}utm_source=filecoin-pin&utm_medium=${medium}&utm_term=${flow}${content}`
}

/** Console network slug by chain id; the console validates and guards on it. */
const CONSOLE_NETWORK_SLUG: Record<number, string> = {
  314: 'mainnet',
  314159: 'calibration',
}

/**
 * A console run on this machine (`CONSOLE_URL` on localhost) can be started
 * against foc-devnet and then knows the devnet; a deployed console does not,
 * and refuses a link that names it.
 */
function networkSlugs(): Record<number, string> {
  let local = false
  try {
    local = ['localhost', '127.0.0.1'].includes(new URL(process.env.CONSOLE_URL ?? '').hostname)
  } catch {
    // No console URL, or not one: the deployed console.
  }
  return local ? { ...CONSOLE_NETWORK_SLUG, 31415926: 'devnet' } : CONSOLE_NETWORK_SLUG
}

/** The console's name for a chain, or undefined when the console has no page for it (devnet, custom RPC). */
export function consoleNetworkSlug(chainId: number): string | undefined {
  return networkSlugs()[chainId]
}

/**
 * Build the console deep link that pre-fills the session address and the
 * scopes it needs on the session-keys authorization page. Carries the
 * network the failure happened on so the console can refuse to prefill
 * when the connected wallet is on a different chain — without it, a
 * calibration remediation link approved by a mainnet-connected wallet
 * silently grants the scopes on mainnet.
 *
 * The address is lowercased: the console validates it with viem's strict
 * `isAddress`, which accepts all-lowercase or a correct EIP-55 checksum but
 * silently rejects mixed-case with a wrong checksum. Lowercase always passes.
 */
export function buildAuthorizeUrl(
  consoleUrl: string,
  sessionAddress: string,
  scopeIds: string[],
  chainId: number
): string {
  const base = trimSlash(consoleUrl)
  return withUtm(
    `${base}/console/session-keys?authorize=${sessionAddress.toLowerCase()}&scopes=${scopeIds.join(',')}${networkParam(chainId)}`,
    'login'
  )
}

/** What `/console/setup` needs to share a Keysmith keyspace with the session key. */
export interface KeyspaceLinkRequest {
  /**
   * The session key's Keysmith key-agreement public key (`publicKeyOf`), which
   * the keyspace grant is wrapped to. Keysmith derives it from the session key
   * but keeps it separate from the signing key.
   */
  publicKey: string
  /** The session key's signature over {@link keyAgreementMessage}, which binds the two. */
  signature: string
  /** Keyspace id, or `new` for the console to start one. */
  keyspace: string
  /** A role (Keysmith scope path) to share instead of the whole keyspace. */
  role?: string | undefined
  /** Loopback URL this process listens on for the keyspace grant; omitted when it only takes a paste. */
  callback?: string | undefined
}

/** What the session key signs so the console can tell the key-agreement key is the session key holder's. */
export const keyAgreementMessage = (publicKey: string) => `Keysmith key agreement key: ${publicKey.toLowerCase()}`

/**
 * The `/console/setup` link for a session key plus a keyspace grant: the
 * console authorizes the key, then shares the keyspace with it.
 */
export function buildSetupUrl(
  consoleUrl: string,
  sessionAddress: string,
  scopeIds: string[],
  chainId: number,
  keyspace: KeyspaceLinkRequest
): string {
  const base = trimSlash(consoleUrl)
  const callback = keyspace.callback ? `&callback=${encodeURIComponent(keyspace.callback)}` : ''
  const role = keyspace.role ? `&role=${encodeURIComponent(keyspace.role)}` : ''
  return withUtm(
    `${base}/console/setup?authorize=${sessionAddress.toLowerCase()}&scopes=${scopeIds.join(',')}${networkParam(chainId)}&pubkey=${keyspace.publicKey.toLowerCase()}&pubkeysig=${keyspace.signature}&keyspace=${keyspace.keyspace}${role}${callback}`,
    'login'
  )
}

/**
 * Revoke deep link: the console opens its revoke dialog on this key, so the
 * owner does not have to find it in the list. `logout` prints it for the key
 * it just dropped locally.
 *
 * Falls back to the plain Session keys page for a network the console has no
 * page for (devnet, a custom RPC) or a session file that never recorded one:
 * the console refuses a revoke link it cannot place.
 */
export function buildRevokeUrl(consoleUrl: string, sessionAddress: string, network: string | undefined): string {
  const page = `${trimSlash(consoleUrl)}/console/session-keys`
  if (network === undefined || !Object.values(networkSlugs()).includes(network)) return withUtm(page, 'revoke')
  // Lowercased for the same reason as buildAuthorizeUrl: strict isAddress.
  return withUtm(`${page}?revoke=${sessionAddress.toLowerCase()}&network=${network}`, 'revoke')
}

/** `&network=<slug>` for a chain the console knows, empty otherwise: the console refuses a link it cannot place. */
function networkParam(chainId: number): string {
  const network = networkSlugs()[chainId]
  return network ? `&network=${network}` : ''
}

/** Deposit the CLI suggests when the account has no funds yet, in whole USDFC. */
export const DEFAULT_SUGGESTED_DEPOSIT_USDFC = 2

function trimSlash(consoleUrl: string): string {
  return consoleUrl.endsWith('/') ? consoleUrl.slice(0, -1) : consoleUrl
}

/** The console home (billing) page. */
export function buildConsoleUrl(consoleUrl: string): string {
  return withUtm(`${trimSlash(consoleUrl)}/console`, 'dashboard')
}

/**
 * Funding deep link: the console pre-fills a deposit-and-approve dialog
 * for the storage service with `deposit` whole USDFC, so topping up and
 * approving the service is one wallet transaction. Carries the network so
 * the console refuses to prefill a deposit for a wallet on another chain.
 */
export function buildFundingUrl(consoleUrl: string, depositUsdfc: number, chainId: number): string {
  return withUtm(
    `${trimSlash(consoleUrl)}/console?deposit=${depositUsdfc}&operator=fwss${networkParam(chainId)}`,
    'fund'
  )
}

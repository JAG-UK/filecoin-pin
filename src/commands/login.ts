/**
 * Commander wiring for `login` and `logout`.
 *
 * `login` pairs this machine with a wallet through the Filecoin Cloud
 * console: it generates a scoped session key, the owner approves it in the
 * browser, and the CLI waits for the grant on-chain. `logout` forgets the
 * saved key.
 */

import { Command, InvalidArgumentError } from 'commander'
import pc from 'picocolors'
import { runLogin, runLogout } from '../login/index.js'
import { addNetworkOptions, rpcUrlOption, scopesOption } from '../utils/cli-options.js'

function parseTimeoutSeconds(value: string): number {
  const seconds = Number(value)
  if (!Number.isInteger(seconds) || seconds <= 0) throw new InvalidArgumentError('Expected a whole number of seconds.')
  return seconds
}

export const loginCommand = new Command('login')
  .description('Log in to your Filecoin account: approve a session key for this machine in the Filecoin Cloud console')
  .addOption(scopesOption('Comma-separated scopes to request (default: createDataSet,addPieces)'))
  .option('--fresh', 'Generate a new session key instead of resuming the saved one')
  .option('--no-browser', 'Print the console link without opening a browser')
  .option('--no-wait', 'Print the console link and exit 2 instead of waiting for the grant; rerun login to check')
  .option('--timeout <seconds>', 'How long to wait for the grant (default: 300)', parseTimeoutSeconds)
  .option(
    '--keyspace <id|new>',
    'Also have the console share a Keysmith encryption keyspace with the key (an existing keyspace id, or new)'
  )
  .option('--role <path>', 'With --keyspace: share only this role (e.g. team/alice) instead of the whole keyspace')
  .addHelpText(
    'after',
    `
${pc.bold('EXAMPLES')}
  $ filecoin-pin login
  $ filecoin-pin login --network calibration
  $ filecoin-pin login --scopes createDataSet,addPieces,schedulePieceRemovals
  $ filecoin-pin login --no-browser --no-wait     # print the link, approve later, rerun to check
  $ filecoin-pin login --keyspace new             # also share a new encryption keyspace
  $ filecoin-pin login --keyspace new --role team/alice   # only one role, in a new keyspace

${pc.bold('FILES')}
  The session key is saved to session.env in the data directory before the
  browser opens (owner-readable only), so an interrupted login resumes the
  same key. \`filecoin-pin logout\` deletes it.

${pc.bold('ENVIRONMENT')}
  CONSOLE_URL   Filecoin Cloud console base URL (default: https://pay.filecoin.cloud)
  BROWSER=none  never open a browser
  NETWORK, RPC_URL  as --network and --rpc-url
  KEYSPACE_GRANT_RETURN  how the keyspace grant comes back from the console:
                both (default; whichever arrives first), loopback (the console
                posts it to this process on 127.0.0.1), or paste (you paste the
                code the console shows)
  KEYSPACE_GRANT_PORT  fixed port for the loopback listener (default: any free
                port), e.g. to forward it over SSH with ssh -L

${pc.bold('EXIT CODES')}
  0  every requested scope was granted
  2  no grant seen in time, --no-wait, or fewer scopes than requested (rerun login to resume)
  1  error, including a network the console has no pairing page for`
  )
  .action(async (options) => {
    try {
      process.exitCode = await runLogin(options)
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = 1
    }
  })
addNetworkOptions(loginCommand).addOption(rpcUrlOption('RPC endpoint'))

export const logoutCommand = new Command('logout')
  .description(
    'Log out: delete the saved session key from this machine (local only; the on-chain grant stays until it expires)'
  )
  .action(() => {
    try {
      runLogout()
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = 1
    }
  })

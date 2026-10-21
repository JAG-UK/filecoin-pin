/**
 * Commander wiring for `keyspace`: encrypted storage in the Keysmith keyspace
 * the owner shared with this login (`login --keyspace`).
 */

import { Command } from 'commander'
import pc from 'picocolors'
import { runKeyspaceGet, runKeyspaceHeader, runKeyspaceImport, runKeyspaceLs, runKeyspacePut } from '../keyspace/run.js'

const action =
  <A extends unknown[]>(run: (...args: A) => Promise<void>) =>
  async (...args: A) => {
    try {
      await run(...args)
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = 1
    }
  }

export const keyspaceCommand = new Command('keyspace')
  .description('Encrypted storage in the keyspace your wallet shared with this login (login --keyspace)')
  .addHelpText(
    'after',
    `
${pc.bold('EXAMPLES')}
  $ filecoin-pin login --keyspace new
  $ filecoin-pin login --keyspace 0x… --role team/alice
  $ filecoin-pin keyspace put notes.txt
  $ filecoin-pin keyspace ls
  $ filecoin-pin keyspace get <pieceCid> -o notes.txt`
  )

keyspaceCommand
  .command('put')
  .description('Encrypt a file in the keyspace and store it, signing as the session key')
  .argument('<file>', 'File to encrypt and store')
  .action(action((file: string) => runKeyspacePut(file)))

keyspaceCommand
  .command('get')
  .description('Download a piece by CID and decrypt it with the keyspace key')
  .argument('<pieceCid>', 'Piece CID')
  .option('-o, --output <file>', 'Write the plaintext here instead of to stdout')
  .action(action((pieceCid: string, options: { output?: string }) => runKeyspaceGet(pieceCid, options.output)))

keyspaceCommand
  .command('ls')
  .description("List the pieces in the keyspace's datasets")
  .action(action(() => runKeyspaceLs()))

keyspaceCommand
  .command('import')
  .description('Save a keyspace grant code from the console, when login could not receive it')
  .argument('<code>', 'The keyspace grant code the console showed')
  .option('--keyspace <id>', 'The keyspace id you asked for (default: accept the one the grant names)')
  .option('--role <path>', 'The role you asked for (default: the whole keyspace)')
  .action(
    action((code: string, options: { keyspace?: string; role?: string }) =>
      runKeyspaceImport(code, options.keyspace, options.role)
    )
  )

keyspaceCommand
  .command('header')
  .description('Print the Authorization header a gating provider checks to serve one piece to this login')
  .argument('<pieceCid>', 'Piece CID')
  .action(action((pieceCid: string) => runKeyspaceHeader(pieceCid)))

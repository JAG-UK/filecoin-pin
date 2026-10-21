# Keyspace grants demo: filecoin-pin + Filecoin Pay console on foc-devnet

A demo, not a release. `filecoin-pin login --keyspace` sends you to the Filecoin Pay console's
`/console/setup` page, which authorizes a session key **and** shares a Keysmith keyspace with it.
The CLI then encrypts, stores, lists and decrypts files in that keyspace through Synapse, without
the wallet.

## What you need

| Piece | Where | Notes |
| --- | --- | --- |
| This branch | `JAG-UK/filecoin-pin`, `demo/keyspace-grants` | The CLI: `login --keyspace`, `keyspace put/get/ls/import/header` |
| The console | `JAG-UK/filecoin-pay-explorer`, `demo/keyspace-grants` | Builds on FilOzone/filecoin-pay-explorer#577 (`/console/setup`), plus a devnet patch and the keyspace step |
| A devnet | `FilOzone/foc-devnet` | Lotus, two Curio providers and the FOC contracts, locally |
| Wallet funding and the inspector | `JAG-UK/keysmith-demos` | `pnpm fund` tops up a browser wallet; `pnpm app` has a byte-level inspector for pieces and grants (needs Keysmith's source, below) |
| Keysmith source, for the inspector only | `JAG-UK/synapse-sdk`, `feat/keysmith` | `pnpm app` loads Keysmith from `KEYSMITH_DIR`, by default `../../synapse-sdk/packages/keysmith` from the keysmith-demos directory |
| Keysmith and FEE | vendored as tarballs in `vendor/` (both repos) | Keysmith built from `JAG-UK/synapse-sdk@9ec535b` (`feat/keysmith`); FEE is `filecoin-encryption-envelope` 0.1.0 |

Tools: Node 24, pnpm through corepack (`corepack enable`), Rust and Docker for foc-devnet, and a
browser wallet such as MetaMask.

## 1. Start the devnet

Follow foc-devnet's README (`cargo run -- init`, the builds, then `cargo run -- start --parallel`).
It writes `~/.foc-devnet/state/latest/devnet-info.json`, which everything below reads.

## 2. Fund a browser wallet

Add the devnet to your wallet: chain id `31415926`, RPC URL = `info.lotus.host_rpc_url` from
`devnet-info.json` (for example `http://localhost:5701/rpc/v1`; the port changes between runs).

```bash
git clone https://github.com/JAG-UK/keysmith-demos.git && cd keysmith-demos
pnpm install
pnpm fund 0xYourWalletAddress            # devnet FIL and USDFC from the devnet's first user
```

## 3. Run the console

```bash
git clone -b demo/keyspace-grants https://github.com/JAG-UK/filecoin-pay-explorer.git
cd filecoin-pay-explorer && pnpm install
cd apps/explorer
FOC_DEVNET=1 \
NEXT_PUBLIC_SUBGRAPH_URL_MAINNET=https://no-subgraph.invalid/mainnet \
NEXT_PUBLIC_SUBGRAPH_URL_CALIBRATION=https://no-subgraph.invalid/calibration \
NEXT_PUBLIC_SUBGRAPH_URL_DEVNET=https://no-subgraph.invalid/devnet \
pnpm exec next dev -p 3780
```

It reads `devnet-info.json` at startup, so restart it whenever you restart the devnet. The
subgraph-backed pages show errors on a devnet; the setup and session-key pages do not need them.

## 4. Build the CLI and log in with a keyspace

```bash
git clone -b demo/keyspace-grants https://github.com/JAG-UK/filecoin-pin.git
cd filecoin-pin && pnpm install && pnpm build
export NETWORK=devnet CONSOLE_URL=http://localhost:3780
node dist/cli.js login --keyspace new            # or an existing keyspace id; add --role team/alice for one role
```

The CLI prints a link to `/console/setup` and opens it. There, with your wallet:

1. **Authorize a session key**: one transaction. Fund and approve storage too if the page asks.
2. **Share keyspace**: one `KeyspaceKey` signature (two the first time this browser starts a
   keyspace), then one `ReadGrant` signature for the claim, which expires with the session key.

The grant comes back to the terminal by itself (a loopback listener on 127.0.0.1), or you paste the
code the page shows. `KEYSPACE_GRANT_RETURN=loopback|paste|both` picks the channel (default `both`),
and `KEYSPACE_GRANT_PORT` fixes the listener's port.

Running `login --keyspace <id>` again when the saved grant still covers that keyspace and role
prints "Nothing to sign" and does not open the console.

## 5. Use the keyspace

```bash
node dist/cli.js keyspace put notes.txt          # encrypts, then stores through Synapse; prints the piece CID
node dist/cli.js keyspace ls                     # pieces in the keyspace
node dist/cli.js keyspace get <pieceCid> -o out.txt
node dist/cli.js keyspace header <pieceCid>      # the Authorization: FOC-Grant header a gating provider would check
```

To see the encrypted bytes as a provider holds them:

```bash
curl -s http://localhost:<pdp_service_url port>/piece/<pieceCid> -o piece.bin
xxd piece.bin | head -20                          # readable Keysmith labels, then ciphertext
```

`pdp_service_url` for each provider is in `devnet-info.json` under `info.pdp_sps`. Try both if the
first returns 404: the upload may be on either, and Curio batches piece adds for a short while.

## Where things are kept

- The login: `session.env` in filecoin-pin's data directory (`~/Library/Application Support/filecoin-pin/`
  on macOS). `KEYSPACE` and `KEYSPACE_GRANT` (the claim chain and wrapped key, base64url) sit beside the
  session key. **The file holds the session private key: don't share or screen-share it.** To show the
  grant only: `grep '^KEYSPACE' "<that path>/session.env"`.
- The keysmith-demos inspector accepts a pasted `KEYSPACE_GRANT=…` line, and pieces fetched by CID.
  It needs a synapse-sdk checkout with its dependencies installed:

  ```bash
  git clone -b feat/keysmith https://github.com/JAG-UK/synapse-sdk.git && (cd synapse-sdk && pnpm install)
  cd keysmith-demos && KEYSMITH_DIR=../synapse-sdk/packages/keysmith pnpm app   # then the Inspector section
  ```

## Known rough edges

- Curio on a devnet left running for days can stop accepting uploads; restart the devnet.
- An upload is confirmed by its transaction receipt: Curio adds pieces in batches, so its status
  endpoint can show 404 for a while.
- Providers do not gate retrieval yet; `keyspace header` only shows what they will check.

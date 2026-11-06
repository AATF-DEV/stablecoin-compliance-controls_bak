# stablecoin-compliance-controls

Reference implementation, safety tests, and gas benchmarks for **ledger-level compliance controls for payment stablecoins**: block, freeze, reject, hold, seize, and burn, as required of permitted payment stablecoin issuers under the U.S. GENIUS Act (Pub. L. 119-27).

This repository accompanies the paper:

> Meng Wang. *Ledger-Level Compliance Controls for Payment Stablecoins: A Reference Architecture for Block, Freeze, and Reject Capabilities under the GENIUS Act.* Preprint, 2026.

> [!WARNING]
> Research code. It has **not been audited** and is not intended for production deployment.

## Key results

![Measured transaction gas](docs/compliance_gas_benchmark.png)

All values are full transaction gas (base cost + calldata + execution − capped refunds), measured with Foundry in isolated-transaction mode.

| Scenario | Tx gas | vs. baseline |
|---|---:|---:|
| ERC-20 transfer, no compliance logic | 33,980 | — |
| **Transfer, packed design (this work), any number of active holds** | **35,034** | **+3.1%** |
| Transfer, separate blacklist mapping | 38,478 | +13.2% |
| Transfer, separate status + aggregate held amount, any number of holds | 40,906 | +20.4% |
| Transfer, separate status + hold array, 0 / 16 holds | 40,975 / 79,487 | +20.6% / +134% |
| Transfer with SMT non-membership proofs, N = 1 / 100,000 | 41,193 / 70,060 | +21% / +106% |

| Compliance action (2-of-3 quorum unless noted) | Tx gas |
|---|---:|
| Freeze, single key (zero-balance account) | 57,611 |
| Freeze, 2-of-4 quorum (zero-balance account) | 85,157 |
| Each additional required signer | ≈ +6,750 |
| Freeze / unfreeze (funded account) | 68,081 / 68,069 |
| Place hold | 91,752 |
| Seize full hold (to a custody account) | 75,476 |
| Burn part of a hold | 81,941 |
| Release hold | 64,142 |
| Update SMT root (any batch size) | ≈ 55,450 |

Batch blocking through a separate mapping exceeds the EIP-7825 per-transaction cap (2²⁴ = 16,777,216 gas) at roughly **690 addresses** per transaction. Raw data is in [`results/`](results/); [`results/summary.md`](results/summary.md) has every table and derived figure of the paper's Section 6.

## Design

| Contract | Role |
|---|---|
| [`EnforcedToken`](src/EnforcedToken.sol) | **Proposed design.** Each account's balance (`uint128`), aggregate held amount (`uint120`), and status (`uint8`) share one storage slot, so a transfer reads compliance state at no extra storage cost. Holds are individually identified records. Seize and burn can only debit an existing hold (two-phase enforcement), and seize can only credit a designated custody account (`isCustody`, set at deployment and changed only by the authority). Every compliance action extends a hash-chained audit log. |
| [`ComplianceAuthority`](src/ComplianceAuthority.sol) | M-of-N signature quorum over an EIP-712 digest that binds the target, exact calldata, an evidence hash (e.g. a reference to a lawful order), a nonce, and a deadline. It is the only address allowed to change compliance state. |
| [`BridgedEnforcedToken`](src/BridgedEnforcedToken.sol) | `EnforcedToken` plus the ERC-7281 bridge interface for issuer-controlled burn-and-mint bridging: bridge-out and bridge-in apply the same compliance checks as transfers, and each allow-listed bridge has rate-limited minting and burning. See [Cross-chain bridging](#cross-chain-bridging). |
| [`XChainAdapter`](src/XChainAdapter.sol) | Minimal allow-listed bridge adapter used in the two-chain tests and benchmarks. |
| [`TieredAuthority`](src/TieredAuthority.sol) | Asymmetric authority of paper Section 5.5: a fast tier for restrictive actions and a delayed, guardian-cancellable slow tier for everything else, with per-epoch budgets, signer rotation, role coverage and HSM-attestation hashes. See [Tiered authority](#tiered-authority). |
| [`BaselineToken`](src/BaselineToken.sol) | Plain ERC-20; cost reference. |
| [`BlacklistToken`](src/BlacklistToken.sol) | Comparison: classic blacklist stored in a separate mapping. |
| [`AggregateHoldsToken`](src/AggregateHoldsToken.sol) | Comparison: separate status mapping plus one aggregate held amount per account (ERC-3643-style partial-freeze bookkeeping); constant-cost transfer path. |
| [`NaiveHoldsToken`](src/NaiveHoldsToken.sol) | Comparison: separate status mapping plus a per-account array of holds summed on every transfer. |
| [`SMTToken`](src/SMTToken.sol) | Comparison: restricted set committed as a depth-160 Sparse Merkle Tree root; every transfer carries compressed non-membership proofs for sender and recipient. |

Account states:

| Status | Outbound | Inbound |
|---|---|---|
| `ACTIVE` (0) | allowed (up to balance − held) | allowed |
| `FROZEN` (1) | blocked | allowed (receive-only) |
| `BLOCKED` (2) | blocked | blocked |

## How it works

### Deployment

1. Deploy an authority: `ComplianceAuthority(signers, M)`, or `TieredAuthority(signers, roles, attestations, guardians, policy)` for the asymmetric policy below.
2. Deploy `EnforcedToken(authority, custodians)` (or `BridgedEnforcedToken` with the same arguments). `custodians` is the initial custody list, the only addresses a seizure can credit. The deployer becomes the `minter`, which can only mint.
3. With `TieredAuthority`, the deployer calls `bindToken(token)` once. The token must name the authority, or the call reverts.
4. For bridging, allow-list each bridge adapter by setting its limits through the authority (`setLimits`).

### One compliance action

1. **Proposal.** Off-chain, the action is fixed as `(target, calldata, e)`, where `e` is the hash of its evidence bundle: the lawful order and its review, or the evidence hash a list update from the ingestion tool carries.
2. **Signing.** Each signer computes `digest(target, calldata, e, nonce, deadline)` on the authority. This is an EIP-712 digest whose domain binds the chain id and the authority's address, so a signature is valid for one action on one chain and one contract. The 65-byte `(r, s, v)` signatures are concatenated in ascending order of signer address.
3. **Submission.** Anyone can submit the signatures:
   - `ComplianceAuthority.execute(...)` checks M signatures and calls the token;
   - `TieredAuthority.execute(...)` (fast tier) checks M_r signatures and the classification, and calls the token at once;
   - `TieredAuthority.queue(...)` (slow tier) checks M_i signatures and records the action; after the delay, anyone calls `executeQueued(...)`; before that, guardians can call `cancel(id, signatures)`, signing `cancelDigest(id)`.
4. **Enforcement.** The token checks the call came from its authority, applies the rules of the action, and appends one entry to its audit log.

### Audit log

Every compliance action updates `logHead` and `logCount` and emits `ComplianceAction(seq, action, paramsHash, evidenceHash, newHead)`, where

```
newHead = keccak256(abi.encode(previousHead, seq, action, paramsHash, evidenceHash))
```

starting from `previousHead = 0` and `seq = 0`. An auditor recomputes the head by replaying the events in order and compares it with `logHead()` and `logCount()`; a missing, reordered or altered event changes the result. The evidence bundle itself stays off-chain.

| `action` | Function | `paramsHash` = keccak256 of |
|---:|---|---|
| 1 | `setStatus(a, s, e)` | `abi.encode(a, s)` |
| 2 | `placeHold(id, a, amt, e)` | `abi.encode(id, a, amt)` |
| 3 | `releaseHold(id, e)` | `abi.encode(id)` |
| 4 | `seize(id, amt, dest, e)` | `abi.encode(id, amt, dest)` |
| 5 | `burnFromHold(id, amt, e)` | `abi.encode(id, amt)` |
| 6 | `blockBatch(accounts, e)` | `abi.encodePacked(accounts)` |
| 7 | `setLimits(bridge, m, u, e)` (bridged token) | `abi.encode(bridge, m, u)` |
| 8 | `setCustody(a, allowed, e)` | `abi.encode(a, allowed)` |

Read-only views for auditors: `statusOf`, `balanceOf`, `heldOf`, `spendableOf`, `holds(id)`, `isCustody`, `logHead`, `logCount`, and on the bridged token the minting and burning limits of each bridge. The repository has no separate replay script; `test/Security.t.sol` (`test_logIsHashChained`) and the Halmos checks verify the formula for every action.

## Tiered authority

`TieredAuthority` can replace `ComplianceAuthority` as the token's authority. `EnforcedToken` is unchanged.

| Tier | Actions | Authorization | Timing |
|---|---|---|---|
| Fast (`execute`) | Restrictive and reversible only: `setStatus` that strictly raises restriction (Active < Frozen < Blocked), `blockBatch`, `placeHold`, `setLimits` that raises neither of a bridge's limits, and `setCustody` that removes a custody account | M_r signatures covering at least `rolesR` roles | Immediate; at most `restrictBudget` accounts restrained per epoch |
| Slow (`queue` → `executeQueued`) | Everything else: unfreeze, unblock, release, seize, burn, adding a custody account, any other target, and every configuration change | M_i > M_r signatures covering at least `rolesI` roles | Executable in [eta, eta + 14 days], eta = queue time + `delay` (≥ 1 h); a disjoint guardian quorum can cancel before execution; seized + burned value capped per epoch, for any target |

Classification happens at execution time and fails closed: anything the fast tier does not recognise as restrictive is rejected there. Configuration (signer rotation, guardians, quorums, roles, delay, budgets) can only be changed by the authority itself, i.e. through the slow tier, and every change must leave a satisfiable policy with 1 ≤ M_r < M_i ≤ N, enough distinct roles, a non-empty guardian quorum and a delay of at least one hour. Signers and guardians are disjoint. The authority binds once to a token that names it as its authority; fast-tier classification and the restriction budget apply to that token, while the value budget counts seizures and burns on any target, so a second token, or a token before binding, cannot escape it. Each signer is registered with a role and the hash of its HSM key attestation; events list the approving signers.

Measured transaction gas (fast tier 2-of-5, slow tier 3-of-5 over two roles, guardians 2-of-3; [`results/tiered.csv`](results/tiered.csv)):

| Action | Tx gas | Same action via `ComplianceAuthority` (2-of-N) |
|---|---:|---:|
| Fast freeze, zero-balance account | 104,531 | 85,157 |
| Fast freeze, funded account | 87,443 | 68,081 |
| Fast place hold | 109,659 | 91,752 |
| Slow seize: queue + execute | 88,584 + 60,713 | 75,476 (no delay) |
| Slow unfreeze: queue + execute | 88,027 + 52,914 | 68,069 (no delay) |
| Guardian cancel (2-of-3) | 37,440 | — |

The fast tier costs about 17,900–19,400 gas more per action than the single-threshold gate: it reads the target's current status to classify the action, updates the budget counter, and logs the approvers.

Proved with Halmos (`test/TieredHalmos.t.sol`, `halmos --contract TieredProofs --loop 3`), with `ecrecover` abstracted so that every outcome of signature recovery is covered, and with the authority's and token's entire storage symbolic (including every slot the constructor wrote):

- **T1** the fast tier only restricts: no status is lowered, no held amount reduced, no balance or supply changed, no existing hold touched, no bridge limit raised, no custody account added, nothing queued; it needs at least M_r approvals covering at least `rolesR` distinct roles, and stays within the restriction budget, which is charged one unit per restrained account (one per address of a `blockBatch`);
- **T2** the fast tier rejects every other target and every non-restrictive selector;
- **T3** queuing needs at least M_i approvals covering at least `rolesI` distinct roles, and sets eta = now + delay;
- **T4** a queued action executes once, only within [eta, eta + grace];
- **T5** a cancelled action never executes, and cancelling needs the guardian quorum;
- **T6** seized plus burned value never exceeds the per-epoch value budget, whatever the target: the bound token, a token not yet bound, or any other contract;
- **T7** configuration changes only through the authority itself and always leaves a valid policy; signers and guardians stay disjoint; and the signer, role and guardian counters behind the policy bounds change exactly with the membership they count, so the bounds refer to the real signer and guardian sets.

Unit tests (`test/Tiered.t.sol`, 26 tests) cover each tier boundary, adding and removing custody accounts, delay and grace, cancellation, both budgets and raising them, the value budget for a second or not-yet-bound token, rotation with attestation hashes, role coverage, disjointness, token binding, and signatures after a chain-id change.

## Cross-chain bridging

`BridgedEnforcedToken` implements the bridge-facing part of ERC-7281 (xERC20). ERC-7281 is a draft: its specification is in an unmerged pull request to the ERC repository ([ethereum/ERCs#89](https://github.com/ethereum/ERCs/pull/89)), and it is discussed on [Ethereum Magicians](https://ethereum-magicians.org/t/erc-7281-sovereign-bridged-tokens/14979). The issuer deploys one canonical token per chain, and allow-listed bridges burn on the source chain and mint on the destination. No collateral is locked and no wrapped token is created, so value on every chain stays under the issuer's controls.

- **Bridge-out** (`burn`) applies the outbound-transfer rules: the holder must be `ACTIVE`, only the spendable balance can leave (held value stays), and a `BLOCKED` bridge cannot burn.
- **Bridge-in** (`mint` by a bridge) applies the inbound-transfer rule: no minting to a `BLOCKED` account. A `FROZEN` account can still receive. A `BLOCKED` bridge cannot mint, so blocking a bridge shuts it in both directions.
- **Rate limits.** Each bridge has a minting limit and a burning limit that refill linearly over one day, as in ERC-7281. They bound what a compromised bridge or relayer can mint. Limits are set only by the authority, and each change is logged in the compliance hash chain.
- **Changing limits through the tiered authority.** Lowering a limit, for example to 0 to shut a compromised bridge, is a fast-tier action. Raising one is a slow-tier action.

ERC-7281 does not synchronize restrictions across chains. Each chain therefore has its own `TieredAuthority` with the same signer set, and signers sign one action per chain. The EIP-712 domain binds the chain id and the authority's address, so a signature cannot be replayed on another chain. The two-chain tests (`test/Bridge.t.sol`, 17 tests; chains simulated by switching `block.chainid`) show the following:
- Supply is conserved across a round trip.
- Holders who are frozen or blocked, and value under hold, cannot leave a chain.
- A blocked bridge can neither burn nor mint.
- Recipient status is enforced on arrival.
- Allowances and allow-listing are required.
- Rate limits refill over time.
- A bridge can be shut down through the fast tier and reopened only through the slow tier.
- A restriction on one chain does not reach the other until it is propagated.
- Signatures and queued actions cannot be replayed across chains.
- Funds that escaped before a freeze stay reachable on the destination chain.

Measured transaction gas ([`results/bridge.csv`](results/bridge.csv)):

| Action | Tx gas |
|---|---:|
| Bridge-out through the adapter (burn) | 56,349 |
| Bridge-in through the adapter (mint) | 47,552 |
| Plain transfer on the bridged token | 35,034 (same as `EnforcedToken`) |
| Fast-tier bridge shutdown, 2-of-5 | 97,953 |

Proved with Halmos (`test/BridgedHalmos.t.sol`, `halmos --contract BridgedProofs`). All thirteen `EnforcedToken` checks are re-run against the bridged token. In addition:
- **B1:** bridge-out happens only through an allow-listed, unblocked bridge within its burning limit. The holder is `ACTIVE`, at most the spendable balance leaves, held value and all other state are untouched, and supply falls by exactly the amount burned. A bridge other than the holder spends exactly the amount from the holder's finite allowance.
- **B2:** bridge-in happens only through an allow-listed, unblocked bridge within its minting limit, never to a `BLOCKED` account, and supply rises by exactly the amount minted.
- **B3:** limits change only through the authority. Each change keeps the available value within the new maxima and appends exactly the specified log entry.

`TieredProofs` additionally proves that the fast tier can never raise a bridge limit (`check_fastBridgeLimits`).

## Sanctions-list ingestion

[`scripts/sanctions_ingest.py`](scripts/sanctions_ingest.py) is the off-chain tool of paper Section 5.3. It turns an OFAC SDN publication into reviewable `blockBatch` actions that fit in a transaction. It signs nothing and submits nothing. Dual-control review, and the decision to sign, remain human steps.

```bash
# reviewer A: build from two independently retrieved copies (two formats, two parsers)
python3 scripts/sanctions_ingest.py build \
  --source <SDN.XML file or https URL> --source <SDN_ADVANCED.XML file or https URL> \
  --previous applied/manifest.json --protect protect.json [--fast-budget N] \
  [--rpc https://... --token 0x...] --out update/
# reviewer B: fetch the sources independently and recompute
python3 scripts/sanctions_ingest.py verify --source ... --source ... \
  --previous applied/manifest.json --protect protect.json --manifest update/manifest.json
```

The table maps each check to the adversary it addresses (paper, Section 3.2).

| Check | Behaviour | Addresses |
|---|---|---|
| Independent copies | At least two sources; every source must yield exactly the same address set. By default these are SDN.XML and SDN_ADVANCED.XML, read by separate parsers. | A3 (feed poisoning) |
| Transport and parsing | HTTPS only, with certificate verification. SHA-256 of every source is recorded. XML with `DOCTYPE`/`ENTITY` is rejected. Size is bounded. | A3 |
| Exact matching | Only `0x` + 40 hex digits is accepted. Mixed-case addresses must pass EIP-55. A malformed or bad-checksum entry stops the build; nothing is dropped silently. Matching is never by similarity. Non-EVM entries under shared tickers (e.g. USDT on Tron) are counted and skipped. | A5 |
| Protected addresses | Any issuer address (custody, authority, bridges) in the list stops the build. | A5 |
| Look-alikes | Additions that share their first and last four hex digits with a known or protected address are flagged for reviewers. | A5 (address poisoning) |
| Stale or rolled-back lists | A publication older than the applied one is refused. So is the same date with a different set. | A3, A5 |
| Diff against the applied list | Additions become `blockBatch` actions. Delistings become one slow-tier `setStatus` each and are marked for case review, because the address may also be restrained by an order. | A5 |
| Batching | Every action stays below the EIP-7825 cap with a 10% margin. The gas model is fitted from `results/batch_update.csv` (worst case: zero-balance targets). Additions are split into fast and slow tier by the remaining fast-tier budget. | A7 |
| Evidence binding | One evidence hash, binding format, assets, publish date and the address list, is carried by every action as `e`. | CO-6 |
| On-chain check (optional) | Reads `statusOf` over RPC. Applied addresses that are not `BLOCKED` are reported as drift (exit code 3). Additions already blocked are noted. Batches never depend on chain state, so the result stays reproducible. | A5 |
| Second reviewer | `verify` recomputes from the reviewer's own copies. Exit 0 only if the evidence hash, address set, diff and every action's calldata are identical. | A1/A2 (shared tooling), A3 |

Outputs of `build`, all in the `--out` directory:
- `manifest.json`: the reproducible result that `verify` compares. It holds the publish date, assets, list hash, evidence hash (and the previous one), the full address list, the diff (`add`, `remove`, `unchanged`), the batching parameters, every action (`tier`, `function`, `addresses`, `calldata`, `estimatedTxGas`, `evidenceHash`) and the warnings.
- `provenance.json`: for each source, its name, SHA-256, size, format, number of entries, non-EVM entries skipped and publish date.
- `report.md`: a human-readable summary for the reviewers: sources and their hashes, warnings, actions with estimated gas, additions, removals (to check against open cases), the on-chain check if `--rpc` was given, and instructions for the second reviewer.

Exit codes:

| Code | `build` | `verify` |
|---:|---|---|
| 0 | manifest written | recomputed result matches the manifest |
| 1 | — | mismatch; the differing fields are printed |
| 2 | stopped: a check failed (`STOP: …`), nothing written | stopped: a check failed |
| 3 | manifest written, but the on-chain state has drifted from the applied list | — |

Testing:
- [`scripts/tests/test_sanctions_ingest.py`](scripts/tests/test_sanctions_ingest.py) has 25 tests. They include the EIP-55 test vectors and a local anvil chain for the drift check.
- `scripts/tests/make_demo.py` generates a deterministic demo in [`data/ingest/`](data/ingest/). Version 1 has 1,000 addresses. Version 2 delists 5 and adds 300, one of which is a look-alike of a protected address.
- [`test/Ingest.t.sol`](test/Ingest.t.sol) executes the demo's actions through `TieredAuthority`, from a fresh deployment and in steady state. Every batch must cost no more than the tool's estimate and stay below 2^24 gas. The on-chain restriction set must equal the list after each version.

Measured cost for the largest batch (646 addresses):
- **15,076,846 gas** on a fresh deployment, against an estimate of 15,098,445.
- **15,008,411 gas** in steady state.
- The cap is 16,777,216.

Notes:
- **Synthetic test data.** The fixtures follow OFAC's XML structure but contain synthetic entries; OFAC's servers were not reachable from the development environment. Before relying on the tool, run `build` and `verify` once on the real publications. OFAC publishes no file hashes or signatures for these exports, so integrity rests on TLS and on the agreement of independently retrieved copies.
- **Source URLs.** Check the current official download URLs on OFAC's Sanctions List Service before configuring them.

## Safety properties

Proved symbolically with [Halmos](https://github.com/a16z/halmos) (`test/Halmos.t.sol`), and additionally checked by stateful fuzzing (`test/Invariants.t.sol`, 256 runs × depth 64 = 16,384 random calls per invariant) and unit tests (`test/Security.t.sol`):

1. **Hold precedence**: seize and burn debit exactly the requested amount from an existing active hold; seize credits only a designated custody account.
2. **Spendable-balance safety**: an account's held amount equals the sum of its active holds and never exceeds its balance.
3. **Freeze safety**: no user-initiated transfer reduces the balance of a frozen or blocked account.
4. **Supply conservation**: total supply equals minted minus burned-from-holds and equals the sum of balances. For `BridgedEnforcedToken`, minted value includes bridge-in mints and burned value includes bridge-out burns.
5. **Quorum**: compliance actions require valid signatures from at least M distinct registered signers (exactly M in `ComplianceAuthority`). Unit tests cover too few signatures, duplicates, outsiders, replay, tampered calldata, and direct calls.
6. **Log completeness**: every compliance action extends the hash-chained log by exactly one entry, and the new head is the specified hash of that entry.

The Halmos checks make the token's entire storage symbolic, so they quantify over all contract states. Each check assumes the invariant for the accounts a call touches, runs one public function with symbolic arguments and caller, and asserts that the invariant still holds and that state changed exactly as specified, including frame conditions that an arbitrary untouched account, an arbitrary other hold record, an arbitrary other allowance entry and an arbitrary other custody-list entry are unchanged. `setCustody` changes exactly one entry (never for address 0) and is logged. Allowance bookkeeping is specified exactly: `transferFrom` spends exactly the amount of a finite allowance and keeps an infinite one, and `approve` sets exactly one entry. Every state-changing public function is covered (`transfer`, `transferFrom`, `approve`, `mint`, `setStatus`, `blockBatch`, `placeHold`, `releaseHold`, `seize`, `burnFromHold`, `setCustody`), and non-authorized callers are proved to be rejected by every compliance function, including `blockBatch` and `setCustody`. Starting from the initial state (no balances, holds or log entries; only the deployment's custody list), this is an inductive proof over all call sequences for invariants 1–4 and 6; each check also asserts that supply and the compliance log change only as specified (non-compliance calls leave the log untouched, and every compliance action appends exactly the specified entry to the head). For invariant 5, Halmos proves the token side (no caller other than the authority can change compliance state); signature verification in `ComplianceAuthority` is covered by unit tests only. `blockBatch` is checked for batches of one or two addresses.

`scripts/mutation_check.py` confirms the proofs are not vacuous: it injects 54 bugs one at a time: seventeen into `EnforcedToken` (a frozen sender allowed to transfer; seizure not reducing the held amount; burning not reducing supply; holds not bounded by the spendable balance; a seizure that deletes a different hold record; `blockBatch` wiping the account's balance; an ordinary transfer advancing the compliance log; `blockBatch` callable without the authority; a seizure logged without its evidence hash; a release logged under the wrong action tag; three allowance errors in `transferFrom` and `approve`; four custody-list errors), twelve into `BridgedEnforcedToken` (each of B1–B3 has at least one, including two allowance errors in bridge-out), and twenty-five into `TieredAuthority` (each of T1–T7 has at least one, including a fast tier that accepts adding a custody account, a `blockBatch` charged as a single account, a value budget that counts only the bound token, three role-coverage errors, and four errors in the signer, role and guardian counters), and requires a Halmos counterexample for each.

```bash
pip install halmos==0.3.3
make prove THREADS=8   # token, bridged-token and tiered-authority proofs  (~3.5 min; ~9 min on two cores)
make mutate THREADS=8  # 54 injected bugs, each must yield a counterexample (~27 min; ~2 h on two cores; CI runs six shards in parallel)
make timing         # how long they took and how many cores they had and used (see "Timing" below)
```

Both targets pass `--solver-threads` to Halmos, set by default to the cores this process may use, and record their own timing. The times reported in the paper were measured with `THREADS=8` (`--solver-threads 8`) on a 12-core, 24-thread desktop CPU; use the same setting to compare a run with the paper (see [Timing](#6-timing-of-the-proofs-and-the-mutation-check)). Halmos keeps only about 1.5 cores busy on average, so the setting matters less than the CPU's single-core speed.

## What is checked

| Check | Where | Count | Run with |
|---|---|---:|---|
| Unit tests: quorum, enforcement semantics, custody list, SMT | `test/Security.t.sol` | 18 | `make test` |
| Unit tests: tiered authority | `test/Tiered.t.sol` | 26 | `make test` |
| Two-chain tests: bridging and propagation | `test/Bridge.t.sol` | 17 | `make test` |
| Stateful invariant fuzzing (256 runs × depth 64) | `test/Invariants.t.sol` | 5 invariants | `make test` |
| Ingestion tool tests | `scripts/tests/test_sanctions_ingest.py` | 25 | `make tools` |
| Ingestion demo executed on-chain | `test/Ingest.t.sol` | 2 | `make ingest` |
| Gas benchmarks | `test/Bench.t.sol` | 7 scenarios | `make bench` |
| Symbolic proofs: token / bridged token / tiered authority | `test/Halmos.t.sol`, `BridgedHalmos.t.sol`, `TieredHalmos.t.sol` | 13 / 16 / 10 | `make prove` |
| Non-vacuity: injected bugs that must each yield a counterexample | `scripts/mutation_check.py` | 54 (17 / 12 / 25) | `make mutate` |

Forge and Halmos print a pass or fail line per test and check, and the mutation check one `KILLED` or `SURVIVED` line per bug and a final `k/n mutants killed`; in CI these are the job logs. The measured outputs are files, described next.

## Output files

Every benchmark CSV in `results/` has the same columns, one row per measured transaction:

| Column | Meaning |
|---|---|
| `variant` | design or action measured |
| `param` | the scenario's parameter (see below) |
| `exec_gas` | gas reported for the transaction minus the standard intrinsic cost |
| `refund` | refund applied, capped at one fifth of the gas used (EIP-3529) |
| `calldata_bytes` | calldata length |
| `intrinsic_gas` | 21,000 + 4 per zero and 16 per non-zero calldata byte |
| `tx_gas` | gas used minus the capped refund, but at least the EIP-7623 calldata floor: the figure reported everywhere in this README and the paper |
| `exceeds_eip7825` | 1 if `tx_gas` is above the 2²⁴ per-transaction cap |

| File | What it measures | `param` |
|---|---|---|
| `transfer_holds.csv` | ERC-20 transfer: `baseline`, `blacklist_mapping`, `separate_aggregate`, `naive_holds`, `enforced_packed` | active holds on the sender |
| `smt_transfer.csv` | transfer with SMT non-membership proofs (`smt_proofs`) | restricted-set size N |
| `quorum.csv` | freezing a zero-balance account: `single_key`, `quorum` (N = M + 2) | required signatures M |
| `batch_update.csv` | restriction-list update through a 2-of-3 quorum: `mapping`, `packed_funded`, `packed_unfunded`, `smt_root` | addresses per batch K |
| `lifecycle.csv` | each enforcement step on a funded account, 2-of-3 quorum | 0 |
| `tiered.csv` | `TieredAuthority`: fast actions, slow queue and execute, guardian cancel | signatures supplied |
| `bridge.csv` | bridge-out, bridge-in, transfer on the bridged token, fast-tier bridge shutdown | 0, or signatures supplied |

Other outputs:
- `results/summary.md`: the paper's Section 6 tables and derived figures (overheads, fits, sums, ratios), computed from the CSVs by `make report`.
- `data/smt_<N>.json`: for N restricted addresses, the SMT root, the non-membership proofs for the benchmark's sender and recipient, and the proof for one restricted address, which the tests use to check that the contract rejects it (`make data`).
- `data/ingest/v1/`, `data/ingest/v2/`: the ingestion demo's `manifest.json`, `provenance.json` and `report.md` (`make ingest`).
- `make plot` writes `compliance_gas_benchmark.pdf` and `.png` into `results/` (git-ignored) or into `PLOT_DIR`; the committed copies of the figure are `docs/compliance_gas_benchmark.pdf` and `.png`.
- `results/timing/` (git-ignored, machine-dependent): one JSON file per timed run of `make prove` and `make mutate`, and `summary.md` and `caption.tex` written from them by `make timing` (see [Timing](#6-timing-of-the-proofs-and-the-mutation-check)).

## Repository layout

```
├── .github/workflows/ci.yml  CI: re-runs tests, benchmarks, data, proofs and mutation check
├── src/                      Solidity contracts
├── test/
│   ├── Bench.t.sol           gas benchmarks → results/*.csv
│   ├── Security.t.sol        unit tests (authorization, state semantics, custody list, SMT rejection)
│   ├── Invariants.t.sol      stateful invariant fuzzing
│   ├── Halmos.t.sol          symbolic proofs of the safety invariants
│   ├── Tiered.t.sol          unit tests for the tiered authority
│   ├── TieredHalmos.t.sol    symbolic proofs for the tiered authority
│   ├── Bridge.t.sol          two-chain tests for bridging and per-chain propagation
│   ├── Ingest.t.sol          on-chain execution of the ingestion tool's actions
│   └── BridgedHalmos.t.sol   symbolic proofs for the bridged token
├── scripts/
│   ├── gen_smt.py            builds SMTs over random restricted addresses → data/
│   ├── plot.py               draws the figure from results/*.csv
│   ├── summarize.py          paper tables from results/*.csv → results/summary.md
│   ├── timed.py              runs a command and records its time and core usage → results/timing/
│   ├── timing_report.py      timing summary and the paper's Halmos-table sentence from results/timing/
│   ├── sanctions_ingest.py   sanctions-list ingestion (build / verify)
│   ├── tests/                tool tests, OFAC-format fixtures, demo generator
│   └── mutation_check.py     non-vacuity check for the Halmos proofs
├── data/                     SMT roots and proofs used by the benchmarks; ingest/ demo outputs
├── results/                  measured gas and summary.md (committed; CI checks they reproduce exactly)
├── docs/                     the figure: .pdf for the paper, .png for this README
├── lib/forge-std/            git submodule, pinned to v1.12.0
├── lib/halmos-cheatcodes/    git submodule (symbolic-testing cheatcodes)
├── foundry.toml
└── Makefile
```

## Step by step

### 1. Install the tools

Foundry **v1.5.1** (forge, cast, anvil). Other versions report gas differently, so the results will not match:

```bash
curl -L https://foundry.paradigm.xyz | bash      # installs foundryup; then open a new shell
foundryup --install v1.5.1
forge --version                                  # must show 1.5.1
```

Python **3.10+**, preferably in a virtual environment. Halmos is needed only for the proofs and the mutation check:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt                  # pycryptodome, matplotlib
pip install halmos==0.3.3
```

On its first build, forge downloads solc 0.8.28, so the first run needs internet access.

### 2. Get the code and build it

```bash
git clone --recursive https://github.com/AATF-DEV/stablecoin-compliance-controls.git
cd stablecoin-compliance-controls
# if you cloned without --recursive: git submodule update --init
make build                                       # "Compiler run successful"
```

### 3. Run everything and collect the results

Each target can be run on its own. Times are indicative, for a two-core machine; for `make prove` and `make mutate` the time with `THREADS=8` on the paper's 12-core, 24-thread machine is given in parentheses. Both measure and record their own (step 6).

| Command | What it does | Writes | Expected output | Time |
|---|---|---|---|---|
| `make test` | unit tests and invariant fuzzing | — | `66 tests passed, 0 failed` | < 1 min |
| `make tools` | ingestion-tool tests (starts a local anvil node) | — | `Ran 25 tests` … `OK` | seconds |
| `make ingest` | regenerates the ingestion demo and executes it on-chain | `data/ingest/` | `2 passed`; batch gas such as `15076846` | seconds |
| `make bench` | gas benchmarks | `results/*.csv` | `7 passed` | < 1 min |
| `make data` | SMT trees and proofs | `data/smt_*.json` | one line per N | ~2 min |
| `make report` | the paper's tables and derived figures from the CSVs | `results/summary.md` | `written to …` | seconds |
| `make plot` | Figure 2 of the paper | `results/compliance_gas_benchmark.{pdf,png}` | `written to …` | seconds |
| `make prove` | symbolic proofs | `results/timing/halmos_*.json` | `13 passed`, `16 passed`, `10 passed` | ~9 min (3.5 min) |
| `make mutate` | non-vacuity check | `results/timing/mutation.json` | `54/54 mutants killed` | ~2 h (27 min) |
| `make timing` | timing summary of the two above | `results/timing/summary.md`, `caption.tex` | `written to …` | seconds |

`make all` runs `test tools ingest prove mutate bench report timing plot` in that order. To keep a log of the whole run:

```bash
make all 2>&1 | tee run.log
```

The results to read are `results/summary.md` (every table and derived figure of Section 6, computed from the CSVs), the CSVs themselves (columns described under [Output files](#output-files)), and the pass/fail lines in the log.

### 4. Check that the published results were reproduced

```bash
make reproduce
```

This runs `test tools ingest bench data report` and then compares `results/` and `data/` with the committed files. It ends with `All committed results and data reproduced exactly.`, or fails and shows the differing lines with `git diff`. It is the same check as CI's reproduce job. The figure is not part of the comparison: its bytes depend on the matplotlib version, which is not pinned.

### 5. Produce the paper's figure

The paper includes `figures/compliance_gas_benchmark.pdf`. Write it straight into the paper's directory:

```bash
make plot PLOT_DIR=/path/to/paper/figures
```

Every number in the figure is read from `results/*.csv`. The repository also keeps a copy of both files, made from the committed CSVs: [`docs/compliance_gas_benchmark.pdf`](docs/compliance_gas_benchmark.pdf) for the paper and the `.png` shown at the top of this README. To refresh them after new measurements: `make plot PLOT_DIR=docs`.

### 6. Timing of the proofs and the mutation check

The proof and mutation times depend on the machine, so they are measured rather than written down. `make prove` and `make mutate` run each Halmos suite (and the whole mutation check) through `scripts/timed.py`, which passes the output through unchanged and then writes `results/timing/<run>.json` with:

| Field | Meaning |
|---|---|
| `wall_s` | wall-clock time of the run, including the build Halmos does first |
| `cpu_s` | user + system CPU time of the run and of every process it waited for, including the solver processes |
| `cores_available` | cores the process may use: the CPU affinity mask, capped by a cgroup CPU quota if one is set (containers, CI). This is what `python3 scripts/timed.py --cores` prints |
| `cores_used_avg` | `cpu_s / wall_s`, the average number of cores actually busy |
| `solver_threads` | the value passed to `halmos --solver-threads` |
| `checks` | every check's result, path count and time as Halmos reports it; for the mutation check, every mutant's result and time |

plus the CPU model, the number of logical CPUs on the machine, OS, Python and Halmos versions, the git commit (`-dirty` if the sources were modified) and whether it ran in CI.

Halmos' own default for `--solver-threads` is the number of CPUs on the machine, which in a container or on a shared runner can exceed the cores the process may actually use. The Makefile therefore always passes the detected number explicitly, and `THREADS` overrides it, so that runs on different machines can be compared under the same setting:

```bash
make prove THREADS=2
make mutate THREADS=4 SHARD=1/6     # one of six shards; timing goes to results/timing/mutation_shard1of6.json
make timing
```

`make timing` writes `results/timing/summary.md` (one row per run, then each suite's checks from slowest to fastest) and `results/timing/caption.tex`, the sentence for the paper's Halmos table. For the run reported in the paper (`make prove THREADS=8` and `make mutate THREADS=8`, AMD Ryzen 9 9900X, 12 cores and 24 threads, WSL2) it reads:

> All pass; wall-clock times: token 13 checks in 18.6 s, bridged token 16 checks in 30.8 s, tiered authority 10 checks in 150 s (24 cores available, 1.5 in use on average, `--solver-threads 8`, Halmos 0.3.3).

The mutation check took 26.8 min wall-clock and 1.7 h CPU time in that run (3.9 cores in use on average). Timing is not part of `make reproduce`, and `results/timing/` is git-ignored.

### Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request, with Foundry v1.5.1 and Halmos 0.3.3:

- **reproduce**: `make test`, `make tools`, `make ingest`, `make bench`, `make data` and `make report`. The job then fails unless `results/*.csv`, `results/summary.md`, `data/ingest/` and `data/smt_*.json` are byte-identical to the committed files.
- **proofs**: `make prove`. The job fails if any proof fails.
- **mutate**: the mutation check in six parallel shards (`make mutate SHARD=I/6`). A shard fails if any of its injected bugs survives, or if any mutant's pattern no longer matches the sources.

The proofs and mutate jobs also run `make timing`, print the summary in the job log and upload `results/timing/` as a build artifact (`timing-proofs`, `timing-mutate-shard0` … `shard5`), so the times of every CI run, with the runner's core count, can be cited. For the mutation check, cite one shard's time or the sum of the shards' CPU time, not the sum of their wall times, since the shards run in parallel.

### Measurement notes

- **Compiler and EVM.** solc 0.8.28 with the optimizer on (200 runs) and `evm_version = prague`. None of the Osaka/Fusaka changes alter the cost of the opcodes used here.
- **Isolation mode is required.** `--isolate` makes each top-level call its own transaction with cold storage. Under isolation, Foundry v1.5.1 reports full transaction gas in `vm.lastCallGas().gasTotalUsed`, including the 21,000 base cost, calldata, and the EIP-7623 floor. The harness subtracts refunds, capped at one fifth (EIP-3529).
- **Pinned forge-std.** forge-std is pinned to v1.12.0 because newer versions change the `Vm.Gas` struct, which breaks `lastCallGas()` decoding on Foundry v1.5.1.
- **Steady state.** Each compliance scenario performs one unmeasured warm-up action first, so the authority nonce and log head are already non-zero, as they would be on a live deployment. Without it, the first `TieredAuthority` action on a fresh deployment costs about 68,000 gas more (for example 172,978 instead of 104,531 for a fast-tier freeze), for the one-time initialisation of the nonce, budget and log slots.
- **EIP-7825 cap.** The cap is not enforced by Foundry. It is checked explicitly in the `exceeds_eip7825` column.
- **SMT data.** Restricted addresses are uniformly random from a fixed seed. Proofs are verified in Python before they are written.

## Limitations

- **Not audited**, and not intended for production use. There is no upgrade path, no signer tooling that decodes and displays what is signed, no intake of lawful orders, and no bridge message transport (the tests use a minimal adapter).
- **Proof scope.** Signature recovery is abstracted in the tiered-authority proofs, and signature verification in `ComplianceAuthority` is covered by unit tests only. Batches are checked for up to two addresses, signature sets for up to three, and bridge-limit changes for two signatures. Halmos itself is trusted. Properties that were not stated, such as fairness of ordering or liveness, are not covered.
- **One nonce for both tiers.** Actions on one chain must be signed in order, and an adversary holding M_r keys can, within the restriction budget, invalidate slow-tier actions that are signed but not yet submitted by submitting fast-tier actions first.
- **Fixed budget epochs.** Two budgets can be spent within a short time around an epoch boundary.
- **Two chains in one EVM.** The propagation tests switch `block.chainid`; they test signing domains and per-chain state, not cross-chain latency.
- **Synthetic sanctions data**, as noted above.
- **Hold size.** A hold record stores a `uint96` amount, so a single hold is limited to 2⁹⁶ − 1 base units (the account's aggregate held amount is a `uint120`).
- **Initial custody list.** The custody accounts set at deployment are emitted as `CustodySet` events but are not part of the hash-chained compliance log; auditors take them from the deployment transaction.
- **Queued actions survive rotation.** Removing a signer does not invalidate slow-tier actions it already helped to queue; they stay executable after their delay unless the guardians cancel them.
- **Bridge-limit refill.** As in ERC-7281, a limit refills at `max / 1 day` per second, rounded down, so a limit below 86,400 base units refills only once the full day has passed.
- **Measurements** are for one compiler version and setting, on the Ethereum cost schedule, with a pre-funded transfer recipient and uniformly random SMT addresses.

## Citation

See [`CITATION.cff`](CITATION.cff), or:

```bibtex
@misc{wang2026ledgercompliance,
  author = {Meng Wang},
  title  = {Ledger-Level Compliance Controls for Payment Stablecoins: A Reference Architecture
            for Block, Freeze, and Reject Capabilities under the {GENIUS} Act},
  year   = {2026},
  note   = {Preprint. Code: https://github.com/AATF-DEV/stablecoin-compliance-controls}
}
```

## License

[MIT](LICENSE). The submodules keep their own licenses: forge-std is MIT/Apache-2.0, and halmos-cheatcodes, used only by the symbolic-proof harnesses in `test/`, is AGPL-3.0.

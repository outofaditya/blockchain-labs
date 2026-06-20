# Blockchain Labs

Three peer-to-peer labs on top of [`py-ipv8`](https://github.com/Tribler/py-ipv8) for the TU Delft Blockchain Engineering course, plus three bonus challenges.

## Table Of Contents

- [Overview](#overview)
- [Repository Layout](#repository-layout)
- [Setup](#setup)
- [Lab 1 — Proof Of Work Over IPv8](#lab-1--proof-of-work-over-ipv8)
- [Lab 2 — Coordinated Group Signing](#lab-2--coordinated-group-signing)
- [Lab 3 — PoW Blockchain Over IPv8](#lab-3--pow-blockchain-over-ipv8)
- [Demonstration](#demonstration)
- [Testing](#testing)
- [Bonus](#bonus)
- [Identity And Keys](#identity-and-keys)
- [Dependencies](#dependencies)

## Overview

All three labs share one IPv8 key pair per member. Lab 1 binds the key to a TU Delft email via PoW; Labs 2 and 3 reuse it.

## Repository Layout

```
.
├── common/
│   ├── banner.py   # shared startup-banner helpers
│   └── paths.py    # repo-root anchor for IPv8 working dir + key lookup
├── labs/
│   ├── one/
│   │   ├── miner.py   # lab 1: standalone proof-of-work miner
│   │   └── client.py  # lab 1: ipv8 client that submits the mined nonce
│   ├── two/
│   │   └── signer.py  # lab 2: coordinated group signing client
│   └── three/
│       ├── chain.py   # lab 3: block primitives, chain, mempool, mining
│       └── node.py    # lab 3: ipv8 node hosting the chain community
├── demo/
│   ├── mine.py     # lab 1 walkthrough
│   ├── sign.py     # lab 2 walkthrough
│   ├── chain.py    # lab 3 walkthrough
│   └── bonus/      # bonus walkthroughs
├── bonus/          # bonus implementations isolated from labs/
├── tests/          # pytest suite mirroring labs/ + common/ + bonus/
├── tasks/          # original assignment briefs
├── keys/           # per-member IPv8 key files (gitignored)
├── pyproject.toml  # ruff and pytest configuration
└── requirements.txt
```

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Python 3.10 or newer is required. Each lab loads its IPv8 identity from a `.pem` file under `keys/`; `KEY_PATH` (env var, defaults to `keys/aditya.pem` for Lab 1) selects which one.

## Lab 1 — Proof Of Work Over IPv8

Mine a SHA-256 nonce over `email + "\n" + github_url + "\n" + nonce_8be` until the digest carries at least 28 leading zero bits, then submit `(email, github_url, nonce)` to the Lab 1 server.

```bash
.venv/bin/python -m labs.one.miner             # mine; copy the printed nonce
.venv/bin/python -m labs.one.client <nonce>    # submit to the server
```

Key choices:

- Pre-computed prefix + cached SHA-256 state — only nonce bytes hashed per attempt.
- One subprocess per core, nonce stride partitioning, linear core scaling.
- `stop_event` polled once per 16 384 attempts; siblings exit within milliseconds of a winner.
- Byte-wise leading-zero check short-circuits on the first non-zero byte.
- Server filtered by published public key — no cross-talk from other peers.

## Lab 2 — Coordinated Group Signing

Three peers register a group, then complete three signing rounds within a 10-second budget. Each round the server issues a 32-byte nonce; all three members sign it; the round's submitter (member N submits round N) bundles the three signatures and ships them back.

```bash
.venv/bin/python -m labs.two.signer <pem_path> <port>
```

Key choices:

- Round number IS the submitter index — no leader-election message.
- Three `asyncio.Event` primitives bridge synchronous handlers and the async driver.
- 1 s retry on `ChallengeRequest` and `SignatureBundle` leans on server idempotency.
- Signature fanned out 3 × at 50 ms spacing for UDP-loss tolerance without ACKs.

## Lab 3 — PoW Blockchain Over IPv8

Three-node PoW blockchain. Each node mines blocks against an 84-byte header, gossips winners to teammates, and answers the server's transaction-submission and chain-walk queries. Longest-chain rule.

```bash
export UNI_EMAIL=<your_email>
export KEY_PATH=keys/<name>.pem
.venv/bin/python -m labs.three.node <port>
```

Key choices:

- Continuous mining; chain-quorum gate ensures the registrar only fires after all three nodes are mutually discovered.
- Side-pool `_pool` retains FORK_BRANCH blocks for later reorg.
- Walk-back orphan resolution with `_inflight` dedup so bursts of orphans spawn one parent request, not many.
- `_try_drain_and_reorg` runs both extend-from-pool and longest-chain-scan on every ingest.
- `adopt_fork` validates the candidate into fresh indexes before swapping — no half-applied fork.
- `@lazy_wrapper(PayloadCls)` on every handler.

## Demonstration

Six local walkthroughs reproduce each lab's mechanics and the three bonus challenges. No live server, no real network. Each ends with a pass banner.

### `demo.mine` — Lab 1 PoW Sweep

Single-thread PoW search at difficulty 20, 22, and 24 to demonstrate per-bit work doubling, then parallel mining at difficulty 26 across every CPU core. Verifies the mined nonce against the difficulty bound and prints worker count, attempt totals, and wall time per step.

```bash
.venv/bin/python -m demo.mine          # ≈ 22 s
```

### `demo.sign` — Lab 2 Round-Robin Signing

Three in-process signers complete three rounds against a mock server with a 30 % UDP-drop model. Each member's signature is retried up to six times per round; per-attempt DROPPED / DELIVERED status is printed so the retry logic is visible. Asserts three distinct submitters within the 10-second budget.

```bash
.venv/bin/python -m demo.sign          # ≈ 4 s
```

### `demo.chain` — Lab 3 Three-Node Sim

Three isolated nodes share no network. Scenario 1: server pushes ten signed txs to node 0, which mines five blocks that gossip to the others; consistency check asserts identical tips and heights. Scenario 2: five blocks mined out-of-order arrive reversed at a second node, walk-back fills the orphan chain. Scenario 3: node 0 builds a five-block chain, node 1 builds a seven-block chain; node 0 atomically adopts the longer chain.

```bash
.venv/bin/python -m demo.chain         # ≈ 50 s
```

### `demo.bonus.difficulty` — Adaptive Retarget

Mines real blocks across four 32-block scenarios with synthesized inter-block gaps to exercise the retarget algorithm: surge (gap 1 s), drought (gap 8 s), steady (gap 2 s), abrupt regime change (fast → slow halfway). Each retarget boundary prints span, expected span, ratio, clamp, and the resulting difficulty transition.

```bash
.venv/bin/python -m demo.bonus.difficulty   # ≈ 53 s
```

### `demo.bonus.reorganize` — Fork Convergence

Three scenarios. (A) Five real signed transactions across three blocks are displaced by a longer empty fork; all five return to the mempool. (B) A 22-deep reorg attempt is rejected by the depth cap. (C) A reorg exactly at the configured max depth is accepted.

```bash
.venv/bin/python -m demo.bonus.reorganize   # ≈ 4 s
```

### `demo.bonus.compact` — Compact Block Propagation

A 100-tx block is packed to compact form (six-byte short IDs salted by the block nonce). (A) Receiver has every tx in mempool: reconstruction in one round, 79 % wire-size reduction. (B) Receiver missing every 15th tx: the protocol identifies missing indices, the sender fills, reconstruction completes. (C) Sender forges a commitment mismatch: receiver returns the abandon sentinel and would fall back to a full block fetch.

```bash
.venv/bin/python -m demo.bonus.compact      # ≈ 3 s
```

## Testing

```bash
.venv/bin/pytest
```

**67 tests pass in ~0.3 s.** 32 over `labs/` + `common/`, 35 over `bonus/`.

## Bonus

Three of the six challenges from the optional bonus brief. Isolated under `bonus/` so the main lab path is untouched.

### Bonus 6 — Adaptive Difficulty (`bonus/difficulty.py`)

PoW retarget targeting a configurable block time. Median-of-11 past-timestamp gate defeats single-miner timestamp manipulation; per-retarget bit delta clamped to ±2 bits prevents oscillation; absolute floor and ceiling bound difficulty.

```bash
.venv/bin/pytest tests/bonus/test_difficulty.py
```

### Bonus 5 — Fork Convergence Polish (`bonus/reorganize.py`)

Wraps `adopt_fork` with (a) mempool restoration of transactions in displaced blocks that don't reappear in the new chain, (b) max-depth gate rejecting long-range fakery, (c) common-ancestor detection.

```bash
.venv/bin/pytest tests/bonus/test_reorganize.py
```

### Bonus 2 — Compact Block Propagation (`bonus/compact.py`)

BIP-152-style. Block ships header + six-byte short IDs salted by `block.nonce`. Receiver reconstructs from local mempool; missing slots trigger a targeted fill round. Commitment mismatch returns an explicit abandon sentinel for full-block fallback. ~79 % wire-size reduction at 100 txs/block.

```bash
.venv/bin/pytest tests/bonus/test_compact.py
```

## Identity And Keys

Your IPv8 private key (`keys/<name>.pem`) is your identity for the entire course. Lab 1 binds your public key to your TU Delft email; Labs 2 and 3 reuse the same key. Lose the key and you lose access to the course server — only Lab 1 supports re-registration of a fresh key against an existing email.

## Dependencies

| Package | Purpose |
| --- | --- |
| [`pyipv8`](https://pypi.org/project/pyipv8/) | Authenticated peer-to-peer networking framework |
| [`pytest`](https://docs.pytest.org/) | Test runner (development only) |
| [`pytest-asyncio`](https://pytest-asyncio.readthedocs.io/) | Async test support for the mining loop integration test |
| [`ruff`](https://docs.astral.sh/ruff/) | Formatter and linter (development only) |

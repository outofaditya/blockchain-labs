# Blockchain Labs

A Python implementation of three progressively involved peer-to-peer protocols built on top of [`py-ipv8`](https://github.com/Tribler/py-ipv8), produced for the **Blockchain Engineering** course at TU Delft.

Each lab is a standalone IPv8 client that joins a course community over UDP, discovers a verified server peer by published public key, and completes a specific cryptographic exchange. The clients are wired to be fast, minimal, and survive UDP loss.

## Table Of Contents

- [Overview](#overview)
- [Repository Layout](#repository-layout)
- [Setup](#setup)
- [Lab 1 — Proof Of Work Over IPv8](#lab-1--proof-of-work-over-ipv8)
- [Lab 2 — Coordinated Group Signing](#lab-2--coordinated-group-signing)
- [Lab 3 — PoW Blockchain Over IPv8](#lab-3--pow-blockchain-over-ipv8)
- [Demonstration](#demonstration)
- [Testing](#testing)
- [Optimizations](#optimizations)
- [Identity And Keys](#identity-and-keys)
- [Dependencies](#dependencies)

## Overview

All three labs share the same foundation: an IPv8 peer that joins a community by its 20-byte identifier, walks the gossip network to find a course-supplied server, exchanges authenticated payloads, and exits cleanly on the expected reply. The lab numbers do not depend on each other at runtime, but the **same IPv8 key pair** identifies the node across all three: the public key registered in Lab 1 is what every later lab proves ownership of.

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
│   ├── mine.py     # local proof-of-work walkthrough at reduced difficulty
│   ├── sign.py     # three in-process signers running the round-robin protocol
│   └── chain.py    # three-node simulation: happy path, walk-back, reorg
├── tests/          # pytest suite mirroring labs/ + common/
├── tasks/          # original assignment briefs
├── keys/           # per-member IPv8 key files (gitignored, one .pem per member)
├── pyproject.toml  # ruff and pytest configuration
└── requirements.txt
```

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Python 3.10 or newer is required. Each lab loads its IPv8 identity from a `.pem` file under `keys/`; `KEY_PATH` (env var, defaults to `keys/aditya.pem` for Lab 1) selects which one. Lab 1 generates a fresh key on first run if the target file does not exist.

## Lab 1 — Proof Of Work Over IPv8

A standalone proof-of-work search followed by a single authenticated submission to the Lab 1 course server.

The miner brute-forces a SHA-256 nonce over `email + "\n" + github_url + "\n" + nonce_8be` until the digest carries at least 28 leading zero bits — roughly 2²⁸ ≈ 268 million expected attempts. Search is parallelised across every CPU core with `multiprocessing`, partitioned by worker stride, with an amortised stop-event check (probed once per 16,384 hashes) so workers spend their time hashing rather than syscalling. First worker to find a winning nonce wins and signals the others to terminate.

The client then joins the Lab 1 IPv8 community, walks the gossip network until it finds the peer whose public key matches the server's published key, and submits `(email, github_url, nonce)` through `ez_send` — IPv8's authenticated send, which signs the payload with the local Ed25519 key. The server re-hashes, verifies the leading zero bits, and replies with an acceptance status.

**Run**:

```bash
.venv/bin/python -m labs.one.miner             # mine; copy the printed nonce
.venv/bin/python -m labs.one.client <nonce>    # submit to the server
```

## Lab 2 — Coordinated Group Signing

Three peers register as a group with the Lab 2 server, then complete three signing rounds within a shared 10-second wall-clock budget.

Each round the server issues a fresh 32-byte nonce. All three members sign it with their respective Ed25519 keys, and one designated submitter bundles the three signatures and ships them back. The submitter rotates per round — pre-assigned via round-robin so no coordination message is needed to decide who drives a given round.

The implementation uses `asyncio.Event` primitives to bridge IPv8's synchronous handlers and the round driver coroutine. The submitter retries challenge requests and bundle submissions on a one-second timeout, exploiting the server's idempotency guarantee to make duplicate sends harmless. Non-submitters fire their signature three times with 50ms spacing to absorb UDP loss without an ACK protocol.

**Run** (one terminal per member, ports distinct for local testing):

```bash
.venv/bin/python -m labs.two.signer <pem_path> <port>
```

The group's three Ed25519 keys are baked into `labs/two/signer.py` in registration order (Pedro → Danil → Aditya); each instance loads its own `.pem`, matches its public key against the constant, derives its `member_index`, and plays the right role for each round.

## Lab 3 — PoW Blockchain Over IPv8

A three-node proof-of-work blockchain. Each node mines blocks against an 84-byte header, gossips winning blocks to teammates, and answers the Lab 3 server's transaction-submission and chain-walking queries. Nodes converge on a single canonical chain via the longest-chain rule. The server walks all three chains and verifies PoW, header linking, body commitment, and three-way consistency.

Mining runs **continuously**: each node mines empty or transaction-bearing blocks against the current tip in a back-to-back loop, so a server transaction is buried in confirmations within seconds of arrival. Registration is gated on a **chain quorum** — one designated registrar (the first member in the canonical group order) only sends `RegisterBlockchain` after all three nodes are mutually discovered in the chain overlay, preventing the server from wasting its retry budget on absent peers. Fork resolution is handled by a side pool of every received block plus a longest-chain scan that atomically swaps tips via `adopt_fork` whenever a sibling chain overtakes the local one.

**Run** (one terminal per member, ports distinct for local testing):

```bash
export UNI_EMAIL=<your_email>
export KEY_PATH=keys/<name>.pem
.venv/bin/python -m labs.three.node <port>
```

The chain's 20-byte community ID, the group ID, and the three member public keys (in registration order: Pedro → Danil → Aditya) are baked into `labs/three/node.py`. Each node matches its own key against `MEMBER_KEYS` and joins the right slot.

## Demonstration

Three local walkthroughs under `demo/` reproduce each lab's mechanics without a live server or real network. Each runs to completion in under a second on a laptop and ends with a pass/fail line.

```bash
.venv/bin/python -m demo.mine    # Lab 1: single-threaded PoW search at difficulty 20, with hash verification
.venv/bin/python -m demo.sign    # Lab 2: three in-process signers, three rounds, round-robin submitters, mock server
.venv/bin/python -m demo.chain   # Lab 3: happy-path consensus, walk-back orphan resolution, longest-chain reorg
```

The Lab 3 demo runs three scripted scenarios in sequence and asserts cross-node consistency at each stage.

## Testing

The pytest suite under `tests/` mirrors the source layout: `tests/labs/three/test_chain.py` covers chain primitives and the mining-loop integration, `tests/labs/one/test_miner.py` covers PoW search and validation, `tests/labs/two/test_signer.py` pins the group-signing invariants, `tests/common/` covers the shared helpers.

```bash
.venv/bin/pytest
```

The suite runs 32 tests in under half a second. Coverage follows a small-to-large progression: primitive functions first (hashing, byte-level zero checks, header packing), then validators, then mempool gates, then chain operations (append, try_extend, adopt_fork), ending with an end-to-end `mining_loop` integration that submits a real signed transaction, mines a block, and verifies the chain advanced.

## Optimizations

### Lab 1 Proof Of Work (`labs/one/miner.py`)

- `Struct(">q")` precompiled — skips format parse per attempt.
- `PREFIX` precomputed — invariant bytes hashed once, not per nonce.
- `sha256(PREFIX).copy()` per nonce — only nonce bytes mixed in.
- Byte-wise zero check with `any(digest[:full])` — short-circuits on first non-zero byte.
- One subprocess per core, nonce stride partitioning — linear core scaling, zero coordination.
- `stop_event` polled every 16,384 attempts — termination within ms, syscall cost invisible.

### Lab 1 IPv8 Submission (`labs/one/client.py`)

- Server filtered by published public key — ignores other students' peers and unsigned traffic.
- `submitted` flag — one send per server match.

### Lab 2 Group Signing (`labs/two/signer.py`)

- `SUBMITTER_BY_ROUND` static — no leader-election message.
- Three `asyncio.Event` primitives — bridge sync IPv8 handlers and async driver.
- 1s retry on `ChallengeRequest` and `SignatureBundle` — leans on server idempotency.
- Signature fanned out 3× at 50 ms spacing — UDP-loss tolerance without ACKs.
- `NonceShare` re-broadcast on timeout — recovers from a lost share without a request protocol.

### Lab 3 Chain Primitives (`labs/three/chain.py`)

- `_HEADER_STRUCT`, `_PREFIX_STRUCT`, `_U64_STRUCT` precompiled — one struct call per packing.
- `_EMPTY_TXS_HASH` constant — empty-body short-circuit.
- `sha256(prefix).copy()` per nonce (mirrors Lab 1).
- `Chain.by_hash` + `by_height` both maintained — O(1) lookup either way.
- `AppendStatus` 5-status enum — handler dispatches without re-validation.
- `adopt_fork` builds fresh indexes then atomically assigns — no half-applied fork.
- Mempool verify-then-dedup — invalid txs never enter the pool.

### Lab 3 Node Behaviour (`labs/three/node.py`)

- `_teammate_keys` as a set — O(1) membership in every handler.
- Single registrar (Pedro) — server sees one sender, not three duplicates.
- `_chain_quorum` gate — registers only after all three nodes are mutually discovered; preserves the server's 3-retry budget.
- `_pool` side-cache for FORK_BRANCH blocks — orphans stay reachable for later reorg.
- Walk-back with `_inflight` dedup — bursts of orphans spawn one parent request, not N.
- `_try_drain_and_reorg` runs both extend-from-pool and longest-chain-scan on every ingest.
- Rebroadcast only on EXTENDS_TIP — prevents amplification on walk-back replies.
- `_unpack` helper centralises auth decode + per-handler allow-list.

### Cross-Cutting

- `set_working_directory(REPO_ROOT)` — IPv8 state pinned to repo root regardless of cwd.
- `set_walker_interval(0.5)` — halved from default, faster peer discovery.
- All logging pinned to CRITICAL — keeps demo output clean.

## Identity And Keys

Your IPv8 private key (`keys/<name>.pem`) is your identity for the entire course. Lab 1 binds your public key to your TU Delft email; Labs 2 and 3 reuse the same key. Lose the key and you lose access to the course server — only Lab 1 supports re-registration of a fresh key against an existing email.

## Dependencies

| Package | Purpose |
| --- | --- |
| [`pyipv8`](https://pypi.org/project/pyipv8/) | Authenticated peer-to-peer networking framework |
| [`pytest`](https://docs.pytest.org/) | Test runner (development only) |
| [`pytest-asyncio`](https://pytest-asyncio.readthedocs.io/) | Async test support for the mining loop integration test |
| [`ruff`](https://docs.astral.sh/ruff/) | Formatter and linter (development only) |

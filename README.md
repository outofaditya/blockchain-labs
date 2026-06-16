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
- [Identity And Keys](#identity-and-keys)
- [Dependencies](#dependencies)

## Overview

All three labs share the same foundation: an IPv8 peer that joins a community by its 20-byte identifier, walks the gossip network to find a course-supplied server, exchanges authenticated payloads, and exits cleanly on the expected reply. The lab numbers do not depend on each other at runtime, but the **same IPv8 key pair** identifies the node across all three: the public key registered in Lab 1 is what every later lab proves ownership of.

## Repository Layout

```
.
├── miner.py        # lab 1: standalone proof-of-work miner
├── client.py       # lab 1: ipv8 client that submits the mined nonce
├── signer.py       # lab 2: coordinated group signing client
├── chain.py        # lab 3: block primitives chain mempool and mining
├── node.py         # lab 3: ipv8 node hosting the chain community
├── tasks/          # original assignment briefs
├── keys/           # per-member IPv8 key files (gitignored, one .pem per member)
└── pyproject.toml  # ruff configuration
```

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install pyipv8 ruff
```

Python 3.10 or newer is required. Each lab loads its IPv8 identity from a `.pem` file under `keys/`; `KEY_PATH` (env var, defaults to `keys/aditya.pem` for Lab 1) selects which one. Lab 1 generates a fresh key on first run if the target file does not exist.

## Lab 1 — Proof Of Work Over IPv8

A standalone proof-of-work search followed by a single authenticated submission to the Lab 1 course server.

The miner brute-forces a SHA-256 nonce over `email + "\n" + github_url + "\n" + nonce_8be` until the digest carries at least 28 leading zero bits — roughly 2²⁸ ≈ 268 million expected attempts. Search is parallelised across every CPU core with `multiprocessing`, partitioned by worker stride, with an amortised stop-event check (probed once per 16,384 hashes) so workers spend their time hashing rather than syscalling. First worker to find a winning nonce wins and signals the others to terminate.

The client then joins the Lab 1 IPv8 community, walks the gossip network until it finds the peer whose public key matches the server's published key, and submits `(email, github_url, nonce)` through `ez_send` — IPv8's authenticated send, which signs the payload with the local Ed25519 key. The server re-hashes, verifies the leading zero bits, and replies with an acceptance status.

**Run**:

```bash
.venv/bin/python miner.py             # mine; copy the printed nonce
.venv/bin/python client.py <nonce>    # submit to the server
```

## Lab 2 — Coordinated Group Signing

Three peers register as a group with the Lab 2 server, then complete three signing rounds within a shared 10-second wall-clock budget.

Each round the server issues a fresh 32-byte nonce. All three members sign it with their respective Ed25519 keys, and one designated submitter bundles the three signatures and ships them back. The submitter rotates per round — pre-assigned via round-robin so no coordination message is needed to decide who drives a given round.

The implementation uses `asyncio.Event` primitives to bridge IPv8's synchronous handlers and the round driver coroutine. The submitter retries challenge requests and bundle submissions on a one-second timeout, exploiting the server's idempotency guarantee to make duplicate sends harmless. Non-submitters fire their signature three times with 50ms spacing to absorb UDP loss without an ACK protocol.

**Run** (one terminal per member, ports distinct for local testing):

```bash
.venv/bin/python signer.py <pem_path> <port>
```

The group's three Ed25519 keys are baked into `signer.py` in registration order (Pedro → Danil → Aditya); each instance loads its own `.pem`, matches its public key against the constant, derives its `member_index`, and plays the right role for each round.

## Lab 3 — PoW Blockchain Over IPv8

A three-node proof-of-work blockchain. Each node mines blocks against an 84-byte header, gossips winning blocks to teammates, and answers the Lab 3 server's transaction-submission and chain-walking queries. Nodes converge on a single canonical chain via the longest-chain rule. The server walks all three chains and verifies PoW, header linking, body commitment, and three-way consistency.

Mining is **demand-gated**: the loop idles behind an `asyncio.Event` until a server transaction lands, then mines exactly enough blocks to satisfy the three-confirmation rule before idling again. Fork resolution is handled by a side pool of every received block plus a longest-chain scan that atomically swaps tips via `adopt_fork` whenever a sibling chain overtakes the local one.

**Run** (one terminal per member, ports distinct for local testing):

```bash
export UNI_EMAIL=<your_email>
export KEY_PATH=keys/<name>.pem
.venv/bin/python node.py <port>
```

The chain's 20-byte community ID, the group ID, and the three member public keys (in registration order: Pedro → Danil → Aditya) are baked into `node.py`. Each node matches its own key against `MEMBER_KEYS` and joins the right slot.

## Identity And Keys

Your IPv8 private key (`keys/<name>.pem`) is your identity for the entire course. Lab 1 binds your public key to your TU Delft email; Labs 2 and 3 reuse the same key. Lose the key and you lose access to the course server — only Lab 1 supports re-registration of a fresh key against an existing email.

## Dependencies

| Package | Purpose |
| --- | --- |
| [`pyipv8`](https://pypi.org/project/pyipv8/) | Authenticated peer-to-peer networking framework |
| [`ruff`](https://docs.astral.sh/ruff/) | Formatter and linter (development only) |

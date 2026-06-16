# Examination Walkthrough

Quick reference for demonstrating the repository end to end. Every command runs inside the project venv from the repo root.

## Order Of Demonstration

1. Test Suite
2. Lab 1 Demo
3. Lab 2 Demo
4. Lab 3 Demo
5. Code Tour With Optimization Highlights

Total runtime under five seconds excluding the code tour.

## Step 1: Test Suite

```bash
.venv/bin/pytest
```

Expected output ends with `32 passed in 0.25s`. Suite covers chain primitives, validator tampering matrix, mempool gating, chain operations, fork adoption, mining loop integration, miner search, and shared helpers.

Talking points
- `tests/labs/three/test_chain.py` covers fifteen cases progressing from hash primitives to fork adoption to a real mining loop integration.
- Coverage mirrors the source tree under `tests/labs/` and `tests/common/`.

## Step 2: Lab 1 Demo

```bash
.venv/bin/python -m demo.mine
```

Expected runtime under one second. Output sections in order: Hash Input, Mining, Verification. Final banner reads `Lab 1 Demo Passed`.

Talking points
- Difficulty is lowered to 20 bits for demo cadence. Spec is 28.
- Verification block recomputes the digest from scratch to prove the mined nonce verifies independently.

## Step 3: Lab 2 Demo

```bash
.venv/bin/python -m demo.sign
```

Expected runtime well under one second. Three rounds run in sequence with the round number matching the submitter member index. Final banner reads `Lab 2 Demo Passed`.

Talking points
- The mock server enforces the same submitter uniqueness check and signature verification as the real lab 2 server.
- Round N is submitted by member N which removes the need for a leader election message.

## Step 4: Lab 3 Demo

```bash
.venv/bin/python -m demo.chain
```

Expected runtime well under one second. Three scenarios run end to end.

1. Happy Path: server submits one tx to node 0 then four blocks are mined and gossiped to nodes 1 and 2. Final heights match across all three nodes.
2. Walk Back Orphan Resolution: block 2 arrives at node 1 before block 1. Node 1 reports `NEEDS_PARENT` and once block 1 lands both blocks apply in order.
3. Longest Chain Reorg: node 0 has a two block chain while node 1 builds a three block chain. Node 0 atomically swaps to node 1 chain via `adopt_fork`.

Talking points
- Every scenario asserts both height agreement and tip hash equality.
- The reorg path exercises the same `adopt_fork` code path the live node uses when it detects a longer sibling chain.

## Step 5: Code Tour With Optimization Highlights

Open files in this order and point at the named symbol.

### Lab 1 Proof Of Work

- `labs/one/miner.py: PREFIX` precomputed prefix so invariant bytes are hashed once.
- `labs/one/miner.py: validate_nonce` byte wise zero check that short circuits on the first non zero byte.
- `labs/one/miner.py: worker` nonce stride partitioning and amortised stop event check probed every 16384 attempts.
- `labs/one/miner.py: mine` one subprocess per core racing for the first valid nonce.

### Lab 2 Group Signing

- `labs/two/signer.py: SignerCommunity.__init__` three asyncio events bridging synchronous ipv8 handlers and the async driver.
- `labs/two/signer.py: _submitter_flow` retry on a one second timeout for the challenge request and the bundle submission.
- `labs/two/signer.py: _non_submitter_flow` signature fanned out three times with 50ms spacing for udp loss resilience.
- `labs/two/signer.py: run_rounds` round number is the submitter index so no leader election message is needed.

### Lab 3 Chain Primitives

- `labs/three/chain.py: _HEADER_STRUCT _PREFIX_STRUCT _U64_STRUCT` precompiled struct packers used everywhere.
- `labs/three/chain.py: _EMPTY_TXS_HASH` precomputed sha256 of empty bytes so empty body blocks short circuit.
- `labs/three/chain.py: mine_block` cached prefix sha256 state per nonce so only the nonce bytes are mixed in.
- `labs/three/chain.py: mine_block_parallel` one subprocess per core with nonce stride partitioning.
- `labs/three/chain.py: Chain` two indexes by_hash and by_height giving O(1) lookups for server queries and fork checks.
- `labs/three/chain.py: AppendStatus` five status enum so the handler dispatches without re running validation.
- `labs/three/chain.py: adopt_fork` validates the full candidate into fresh indexes then atomically swaps so there is no half applied state.
- `labs/three/chain.py: Mempool.add` signature verify then dedup so invalid transactions never enter the pool.

### Lab 3 Node Behaviour

- `labs/three/node.py: ChainCommunity.__init__` teammate keys held as a set for O(1) membership in every handler.
- `labs/three/node.py: RegistrationCommunity.is_registrar` first canonical member is the sole registrar so the server sees one sender.
- `labs/three/node.py: _chain_quorum` register only after all three nodes are mutually discovered.
- `labs/three/node.py: _pool` side cache of every received non tip block so orphans stay reachable for later reorg.
- `labs/three/node.py: _kick_walk_back` requests a missing parent with inflight dedup so bursts of orphans spawn one parent request not many.
- `labs/three/node.py: _try_drain_and_reorg` greedy tip extension followed by a longest chain scan on every ingest.

## Architecture Summary

Three lab clients sharing one IPv8 key pair per member.

- Lab 1 is a standalone miner plus a one shot IPv8 submission client.
- Lab 2 is a coordinated three peer signing round under a ten second budget.
- Lab 3 is a three node proof of work blockchain answering server queries about height tip block and transaction inclusion.

Shared helpers live under `common/` and demo runners live under `demo/`.

## Cold Clone Verification

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest
.venv/bin/python -m demo.mine
.venv/bin/python -m demo.sign
.venv/bin/python -m demo.chain
```

Each command should return zero status and the demos should finish at their respective pass banners.

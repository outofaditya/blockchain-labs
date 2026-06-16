import time

from ipv8.keyvault.crypto import default_eccrypto

from common.banner import divider, rows, rule
from labs.three.chain import (
    GENESIS,
    AppendStatus,
    Block,
    Chain,
    Mempool,
    Tx,
    assemble_candidate,
    mine_block,
)

DIFFICULTY = 8


# wallclock timestamp used for both txs and block headers
def now() -> int:
    return int(time.time())


# builds a real Ed25519-signed transaction from a fresh keypair
def make_signed_tx(data: bytes) -> Tx:
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    ts = now()
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    return Tx(sender, data, ts, sig)


# mines one block on chain's tip including every mempool tx, then appends
def mine_one(chain: Chain, mempool: Mempool, difficulty: int = DIFFICULTY) -> Block:
    txs_hash, tx_hashes = assemble_candidate(mempool)
    timestamp = now()
    prev_hash = chain.tip_hash
    nonce, _ = mine_block(prev_hash, txs_hash, difficulty, timestamp)
    block = Block(prev_hash, txs_hash, timestamp, difficulty, nonce, tx_hashes)
    assert chain.append(block)
    mempool.remove(list(tx_hashes))
    return block


# delivers a foreign block to a chain via the same try_extend path the node uses
def deliver(chain: Chain, block: Block) -> AppendStatus:
    status, _ = chain.try_extend(block)
    return status


# scenario 1: server submits tx, node 0 mines, all three nodes converge
def happy_path() -> None:
    rule("SCENARIO 1: HAPPY PATH")
    print("Server submits one tx. Node 0 mines four blocks (1 + 3 confirmations).")
    print("Each block is gossiped to nodes 1 and 2.\n")
    divider()
    nodes = [(Chain(), Mempool()) for _ in range(3)]
    tx = make_signed_tx(b"hello chain")
    print(f"[server] submitting tx ({tx.data!r}) to node 0")
    assert nodes[0][1].add(tx) is not None
    for confirmation in range(1, 5):
        block = mine_one(*nodes[0])
        print(f"[node 0] mined block height={nodes[0][0].height}")
        for i, (chain, _) in enumerate(nodes[1:], start=1):
            status = deliver(chain, block)
            print(f"  -> node {i}: {status.name}, height={chain.height}")
    divider()
    heights = [c.height for c, _ in nodes]
    tips = {c.tip_hash for c, _ in nodes}
    rows(
        [
            ("Heights", heights),
            ("Unique tips", len(tips)),
            (
                "Result",
                "OK" if len(tips) == 1 and all(h == 4 for h in heights) else "FAIL",
            ),
        ]
    )
    assert all(h == 4 for h in heights) and len(tips) == 1


# scenario 2: orphan arrives before its parent, walk-back fills the gap
def walk_back() -> None:
    rule("SCENARIO 2: WALK-BACK ORPHAN RESOLUTION")
    print("Node 0 mines block1 and block2. Block2 reaches node 1 first.")
    print("Node 1 detects the orphan, requests block1, then both land in order.\n")
    divider()
    a, b = Chain(), Chain()
    mp = Mempool()
    block1 = mine_one(a, mp)
    block2 = mine_one(a, mp)
    print("[node 0] mined block1 (h=1) and block2 (h=2)")
    print("[network] block2 arrives at node 1 first; block1 delayed")
    status, parent_hash = b.try_extend(block2)
    print(
        f"[node 1] try_extend(block2) -> {status.name}, parent={parent_hash[:8].hex()}..."
    )
    assert status is AppendStatus.NEEDS_PARENT
    print("[network] block1 arrives at node 1 (walk-back fulfilled)")
    s1 = deliver(b, block1)
    print(f"[node 1] try_extend(block1) -> {s1.name}, height={b.height}")
    s2 = deliver(b, block2)
    print(f"[node 1] try_extend(block2) -> {s2.name}, height={b.height}")
    divider()
    rows(
        [
            ("Final height", b.height),
            ("Tip matches node 0", a.tip_hash == b.tip_hash),
        ]
    )
    assert b.height == 2 and a.tip_hash == b.tip_hash


# scenario 3: shorter chain swaps to a longer sibling via adopt_fork
def reorg() -> None:
    rule("SCENARIO 3: LONGEST-CHAIN REORG")
    print("Node 0 mines 2 blocks. Node 1 mines 3 blocks independently.")
    print("Node 0 receives node 1's chain and atomically swaps to it.\n")
    divider()
    a, b = Chain(), Chain()
    mp_a, mp_b = Mempool(), Mempool()
    long_chain = [GENESIS]
    for _ in range(2):
        mine_one(a, mp_a)
    for _ in range(3):
        long_chain.append(mine_one(b, mp_b))
    print(f"[node 0] short chain  height={a.height}, tip={a.tip_hash[:8].hex()}...")
    print(f"[node 1] long chain   height={b.height}, tip={b.tip_hash[:8].hex()}...")
    accepted = a.adopt_fork(long_chain)
    print(
        f"[node 0] adopt_fork() -> {accepted}, new height={a.height}, new tip={a.tip_hash[:8].hex()}..."
    )
    divider()
    rows(
        [
            ("New height", a.height),
            ("Tip matches node 1", a.tip_hash == b.tip_hash),
        ]
    )
    assert accepted and a.height == 3 and a.tip_hash == b.tip_hash


def main() -> None:
    rule("LAB 3 LOCAL SIMULATION")
    print("Three scenarios. No IPv8 wire, no server, no peer discovery.")
    print("Pure chain primitives demonstrating the protocol end-to-end.\n")
    happy_path()
    print()
    walk_back()
    print()
    reorg()
    print()
    rule("ALL SCENARIOS PASSED")


if __name__ == "__main__":
    main()

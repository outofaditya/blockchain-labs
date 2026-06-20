import time

from ipv8.keyvault.crypto import default_eccrypto

from labs.three.chain import (
    Tx,
    Block,
    Chain,
    GENESIS,
    Mempool,
    mine_block,
    AppendStatus,
    assemble_candidate,
)
from common.banner import rule, rows, divider, section

# difficulty tuned so each block costs visible compute without dragging the run
DIFFICULTY = 22
# pause between observable events keeps the cadence readable on stage
PAUSE = 0.3


# wall clock timestamp used for both txs and block headers
def now() -> int:
    return int(time.time())


# builds a real ed25519 signed transaction from a fresh keypair
def make_signed_tx(data: bytes) -> Tx:
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    ts = now()
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    return Tx(sender, data, ts, sig)


# mines one block on the chain tip including every mempool tx then appends it
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


# prints a compact snapshot of every node tip height for cross node visibility
def snapshot_nodes(label, nodes):
    heights = " ".join(f"node{i}={c.height}" for i, (c, _) in enumerate(nodes))
    print(f"  {label}: {heights}")


# scenario one server submits multiple transactions and all three nodes converge
def happy_path() -> None:
    rule("Scenario One Multi Transaction Convergence")
    print("Server Submits Ten Transactions To Node Zero")
    print("Node Zero Mines Five Blocks That Land On Every Node\n")
    section("Setup")
    nodes = [(Chain(), Mempool()) for _ in range(3)]
    txs = [make_signed_tx(f"payment-{i}".encode()) for i in range(10)]
    print(f"[Server] Pushing {len(txs)} Signed Transactions To Node 0 Mempool")
    for tx in txs:
        assert nodes[0][1].add(tx) is not None
    print(f"[Node 0] Mempool Size = {len(nodes[0][1])}")
    snapshot_nodes("Heights Before", nodes)
    time.sleep(PAUSE)

    section("Mining And Gossip")
    for round_num in range(1, 6):
        # node 0 mines the next block which sweeps mempool then gossips to peers
        block = mine_one(*nodes[0])
        height = nodes[0][0].height
        print(
            f"[Node 0] Mined Block Height={height} "
            f"Txs={len(block.tx_hashes)} "
            f"Mempool={len(nodes[0][1])}"
        )
        for i, (chain, _) in enumerate(nodes[1:], start=1):
            status = deliver(chain, block)
            print(f"  -> Node {i}: {status.name}, Height={chain.height}")
        time.sleep(PAUSE)

    divider()
    heights = [c.height for c, _ in nodes]
    tips = {c.tip_hash for c, _ in nodes}
    mempools = [len(m) for _, m in nodes]
    converged = len(tips) == 1 and all(h == 5 for h in heights)
    rows(
        [
            ("Heights", heights),
            ("Mempools", mempools),
            ("Unique Tips", len(tips)),
            ("Status", "Converged" if converged else "Inconsistent"),
        ]
    )
    assert converged


# scenario two walk back resolution across a five block orphan chain
def walk_back() -> None:
    rule("Scenario Two Five Block Walk Back Resolution")
    print("Node Zero Mines Five Blocks Out Of Order")
    print("Node One Receives Them Newest First And Must Walk Back\n")
    section("Sender Side Build")
    a = Chain()
    mp = Mempool()
    blocks = []
    for i in range(5):
        # each block carries a single signed tx so the body commitment is non trivial
        mp.add(make_signed_tx(f"walkback-{i}".encode()))
        blk = mine_one(a, mp)
        blocks.append(blk)
        print(
            f"[Node 0] Mined Block {i + 1} Height={a.height} Tip={a.tip_hash[:8].hex()}..."
        )
        time.sleep(PAUSE)
    print(f"[Node 0] Final Tip Height = {a.height}")

    section("Receiver Side Out Of Order Ingest")
    b = Chain()
    # ship blocks in reverse so every non genesis block lands as an orphan first
    for blk in reversed(blocks):
        status, parent_hash = b.try_extend(blk)
        print(
            f"[Node 1] try_extend(block at h={blocks.index(blk) + 1}) -> {status.name} "
            f"parent={parent_hash[:8].hex() if parent_hash else 'n/a'}..."
        )
        time.sleep(PAUSE)

    section("Forward Pass After Walk Back")
    # apply blocks in order now to simulate the walk back resolution
    for blk in blocks:
        status = deliver(b, blk)
        print(
            f"[Node 1] Re Ingest Block Height={blocks.index(blk) + 1} -> {status.name}"
        )
        time.sleep(PAUSE)

    divider()
    resolved = b.height == 5 and a.tip_hash == b.tip_hash
    rows(
        [
            ("Sender Tip Height", a.height),
            ("Receiver Tip Height", b.height),
            ("Tips Match", a.tip_hash == b.tip_hash),
            ("Status", "Walk Back Resolved" if resolved else "Orphan Still Stuck"),
        ]
    )
    assert resolved


# scenario three deep reorg with mempool sized fork choice
def reorg() -> None:
    rule("Scenario Three Deep Reorg Seven Versus Five")
    print("Node Zero Builds A Five Block Chain")
    print("Node One Builds A Seven Block Chain In Parallel")
    print("Node Zero Adopts The Longer Chain Atomically\n")

    section("Build Short Chain On Node Zero")
    a = Chain()
    mp_a = Mempool()
    for i in range(5):
        mp_a.add(make_signed_tx(f"short-{i}".encode()))
        mine_one(a, mp_a)
        print(f"[Node 0] Short Tip Height={a.height} Tip={a.tip_hash[:8].hex()}...")
        time.sleep(PAUSE)

    section("Build Long Chain On Node One")
    b = Chain()
    mp_b = Mempool()
    long_chain = [GENESIS]
    for i in range(7):
        mp_b.add(make_signed_tx(f"long-{i}".encode()))
        block = mine_one(b, mp_b)
        long_chain.append(block)
        print(f"[Node 1] Long Tip Height={b.height} Tip={b.tip_hash[:8].hex()}...")
        time.sleep(PAUSE)

    section("Atomic Adoption On Node Zero")
    print(f"[Node 0] Pre Adopt Tip Height={a.height} Tip={a.tip_hash[:8].hex()}...")
    accepted = a.adopt_fork(long_chain)
    print(f"[Node 0] adopt_fork() -> {accepted}")
    print(f"[Node 0] Post Adopt Tip Height={a.height} Tip={a.tip_hash[:8].hex()}...")
    time.sleep(PAUSE)

    divider()
    reorged = accepted and a.height == 7 and a.tip_hash == b.tip_hash
    rows(
        [
            ("New Height", a.height),
            ("Matches Node One Tip", a.tip_hash == b.tip_hash),
            ("Status", "Reorg Adopted" if reorged else "Reorg Rejected"),
        ]
    )
    assert reorged


# runs the three scenarios end to end and prints the final pass banner
def main() -> None:
    rule("Lab Three Local Simulation")
    print("Three Scenarios. No IPv8 Wire, No Server, No Peer Discovery.")
    print(f"Pure Chain Primitives At Mining Difficulty {DIFFICULTY}.")
    print()
    happy_path()
    print()
    walk_back()
    print()
    reorg()
    print()
    rule("All Scenarios Passed")


if __name__ == "__main__":
    main()

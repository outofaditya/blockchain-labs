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
from common.banner import rule, rows, divider

# difficulty kept low so every scenario finishes within a fraction of a second
DIFFICULTY = 8


# wall clock timestamp used for both txs and block headers
def now() -> int:
    return int(time.time())


# builds a real ed25519 signed transaction from a fresh keypair
def make_signed_tx(data: bytes) -> Tx:
    # generate a throwaway keypair and sign the canonical preimage bytes
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    ts = now()
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    return Tx(sender, data, ts, sig)


# mines one block on the chain tip including every mempool tx then appends it
def mine_one(chain: Chain, mempool: Mempool, difficulty: int = DIFFICULTY) -> Block:
    # snapshot the candidate inputs from the chain and mempool
    txs_hash, tx_hashes = assemble_candidate(mempool)
    timestamp = now()
    prev_hash = chain.tip_hash
    # search for a valid nonce and assemble the block from the result
    nonce, _ = mine_block(prev_hash, txs_hash, difficulty, timestamp)
    block = Block(prev_hash, txs_hash, timestamp, difficulty, nonce, tx_hashes)
    # append to the chain and clear the included txs from the mempool
    assert chain.append(block)
    mempool.remove(list(tx_hashes))
    return block


# delivers a foreign block to a chain via the same try_extend path the node uses
def deliver(chain: Chain, block: Block) -> AppendStatus:
    status, _ = chain.try_extend(block)
    return status


# scenario 1 server submits tx node 0 mines and all three nodes converge
def happy_path() -> None:
    rule("Scenario 1: Happy Path")
    print("Server Submits One Tx. Node 0 Mines Four Blocks (1 + 3 Confirmations).")
    print("Each Block Is Gossiped To Nodes 1 And 2.\n")
    divider()
    # spawn three isolated nodes each with its own chain and mempool
    nodes = [(Chain(), Mempool()) for _ in range(3)]
    # the mock server submits one signed tx to node 0 only
    tx = make_signed_tx(b"hello chain")
    print(f"[Server] Submitting Tx ({tx.data!r}) To Node 0")
    assert nodes[0][1].add(tx) is not None
    # node 0 mines the tx into a block then mines three confirmations on top
    for _ in range(1, 5):
        block = mine_one(*nodes[0])
        print(f"[Node 0] Mined Block Height={nodes[0][0].height}")
        # each block is delivered to the other two nodes via try_extend
        for i, (chain, _) in enumerate(nodes[1:], start=1):
            status = deliver(chain, block)
            print(f"  -> Node {i}: {status.name}, Height={chain.height}")
    divider()
    # consistency check confirms every node ended at the same tip
    heights = [c.height for c, _ in nodes]
    tips = {c.tip_hash for c, _ in nodes}
    rows(
        [
            ("Heights", heights),
            ("Unique Tips", len(tips)),
            (
                "Result",
                "OK" if len(tips) == 1 and all(h == 4 for h in heights) else "FAIL",
            ),
        ]
    )
    assert all(h == 4 for h in heights) and len(tips) == 1


# scenario 2 orphan arrives before its parent and walk back fills the gap
def walk_back() -> None:
    rule("Scenario 2: Walk-Back Orphan Resolution")
    print("Node 0 Mines Block1 And Block2. Block2 Reaches Node 1 First.")
    print("Node 1 Detects The Orphan, Requests Block1, Then Both Land In Order.\n")
    divider()
    # node 0 mines two blocks while node 1 sits empty
    a, b = Chain(), Chain()
    mp = Mempool()
    block1 = mine_one(a, mp)
    block2 = mine_one(a, mp)
    print("[Node 0] Mined Block1 (h=1) And Block2 (h=2)")
    # block2 reaches node 1 before its parent landing as an orphan
    print("[Network] Block2 Arrives At Node 1 First; Block1 Delayed")
    status, parent_hash = b.try_extend(block2)
    parent_preview = parent_hash[:8].hex()
    print(f"[Node 1] try_extend(block2) -> {status.name}, Parent={parent_preview}...")
    assert status is AppendStatus.NEEDS_PARENT
    # the delayed parent finally arrives and both blocks now land in order
    print("[Network] Block1 Arrives At Node 1 (Walk-Back Fulfilled)")
    s1 = deliver(b, block1)
    print(f"[Node 1] try_extend(block1) -> {s1.name}, Height={b.height}")
    s2 = deliver(b, block2)
    print(f"[Node 1] try_extend(block2) -> {s2.name}, Height={b.height}")
    divider()
    rows(
        [
            ("Final Height", b.height),
            ("Matches Node 0", a.tip_hash == b.tip_hash),
        ]
    )
    assert b.height == 2 and a.tip_hash == b.tip_hash


# scenario 3 shorter chain swaps to a longer sibling via adopt_fork
def reorg() -> None:
    rule("Scenario 3: Longest-Chain Reorg")
    print("Node 0 Mines 2 Blocks. Node 1 Mines 3 Blocks Independently.")
    print("Node 0 Receives Node 1's Chain And Atomically Swaps To It.\n")
    divider()
    # node 0 builds a two block chain
    a, b = Chain(), Chain()
    mp_a, mp_b = Mempool(), Mempool()
    long_chain = [GENESIS]
    for _ in range(2):
        mine_one(a, mp_a)
    # node 1 builds a three block chain in parallel and tracks every block
    for _ in range(3):
        long_chain.append(mine_one(b, mp_b))
    print(f"[Node 0] Short Chain  Height={a.height}, Tip={a.tip_hash[:8].hex()}...")
    print(f"[Node 1] Long Chain   Height={b.height}, Tip={b.tip_hash[:8].hex()}...")
    # node 0 receives node 1 chain and atomically swaps to the longer tip
    accepted = a.adopt_fork(long_chain)
    new_tip = a.tip_hash[:8].hex()
    print(
        f"[Node 0] adopt_fork() -> {accepted}, New Height={a.height}, "
        f"New Tip={new_tip}..."
    )
    divider()
    rows(
        [
            ("New Height", a.height),
            ("Matches Node 1", a.tip_hash == b.tip_hash),
        ]
    )
    assert accepted and a.height == 3 and a.tip_hash == b.tip_hash


# runs all three scenarios back to back and prints a final pass banner
def main() -> None:
    rule("Lab 3 Local Simulation")
    print("Three Scenarios. No IPv8 Wire, No Server, No Peer Discovery.")
    print("Pure Chain Primitives Demonstrating The Protocol End-To-End.\n")
    happy_path()
    print()
    walk_back()
    print()
    reorg()
    print()
    rule("All Scenarios Passed")


if __name__ == "__main__":
    main()

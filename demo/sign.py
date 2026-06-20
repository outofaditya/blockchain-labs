import os
import time
import random

from ipv8.keyvault.crypto import default_eccrypto

from common.banner import rule, rows, divider, section

# total wall clock budget the real lab 2 server enforces across three rounds
GROUP_BUDGET_SECONDS = 10.0
# how often the simulated network drops a signature share to exercise retry paths
LOSS_RATE = 0.3
# how many fan out attempts the submitter retries before declaring a round failed
MAX_ATTEMPTS = 6
# observable pause between protocol events
PAUSE = 0.4
# deterministic seed so the demo is reproducible across runs
RNG = random.Random(20260620)


# in memory mirror of the lab 2 server state for a single group
class MockServer:
    def __init__(self, member_pubs: list[bytes]) -> None:
        self.member_pubs = member_pubs
        self.group_id = "demo_group_" + os.urandom(4).hex()
        self.round = 0
        self.submitters_seen: set[bytes] = set()
        self.start_time: float | None = None

    # issues a fresh 32 byte nonce and starts the wall clock budget on round 1
    def challenge(self) -> tuple[bytes, int, float]:
        self.round += 1
        if self.start_time is None:
            self.start_time = time.time()
        nonce = os.urandom(32)
        deadline = self.start_time + GROUP_BUDGET_SECONDS
        return nonce, self.round, deadline

    # validates a three signature bundle against the registered member keys
    def submit(
        self, nonce: bytes, round_num: int, sigs: list[bytes], submitter_pub: bytes
    ) -> str:
        if submitter_pub in self.submitters_seen:
            return "Rejected: Submitter Already Used In A Previous Round"
        for i, sig in enumerate(sigs):
            pub = default_eccrypto.key_from_public_bin(self.member_pubs[i])
            if not default_eccrypto.is_valid_signature(pub, nonce, sig):
                return f"Rejected: Invalid Signature From Member {i + 1}"
        self.submitters_seen.add(submitter_pub)
        elapsed = time.time() - self.start_time
        return (
            f"Round {round_num} Recorded At {elapsed:.2f}s "
            f"Of {GROUP_BUDGET_SECONDS:.0f}s"
        )


# tracks per round signature collection state on the submitter side
class SignatureCollector:
    def __init__(self):
        self.signatures: dict[int, bytes] = {}
        self.attempts = 0
        self.dropped = 0

    def receive(self, member_index: int, signature: bytes, dropped: bool):
        self.attempts += 1
        if dropped:
            self.dropped += 1
            return
        self.signatures[member_index] = signature

    def complete(self) -> bool:
        return len(self.signatures) == 3


# simulates one round with the lossy network model and retry path
def run_round(server: MockServer, keys, pubs, round_num):
    section(f"Round {round_num}")
    submitter_index = round_num
    nonce, issued_round, _deadline = server.challenge()
    assert issued_round == round_num
    print(f"[Server] Issued Nonce={nonce[:8].hex()}... For Round {issued_round}")
    print(f"[Submitter] Role = Member {submitter_index}")
    time.sleep(PAUSE)

    collector = SignatureCollector()

    # submitter retries each missing member up to MAX_ATTEMPTS mirroring protocol fan out
    print(f"[Members] Signing And Fanning Out (Loss Rate {int(LOSS_RATE * 100)}%)")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        if collector.complete():
            break
        for member_index in (1, 2, 3):
            if member_index in collector.signatures:
                continue
            key = keys[member_index - 1]
            sig = default_eccrypto.create_signature(key, nonce)
            dropped = RNG.random() < LOSS_RATE
            collector.receive(member_index, sig, dropped)
            tag = "DROPPED" if dropped else "DELIVERED"
            print(f"  Attempt {attempt} Member {member_index} -> {tag}")
        time.sleep(PAUSE)

    print(
        f"[Submitter] Collected {len(collector.signatures)} Of 3 "
        f"After {collector.attempts} Attempts ({collector.dropped} Drops)"
    )
    if not collector.complete():
        print("[Submitter] Aborting Round Cannot Build Bundle")
        return False

    # submit the bundle to the server and read back the verdict
    sigs_in_order = [collector.signatures[i] for i in (1, 2, 3)]
    result = server.submit(nonce, round_num, sigs_in_order, pubs[submitter_index - 1])
    print(f"[Server] {result}")
    time.sleep(PAUSE)
    return result.startswith("Round")


# entry point that walks the three round protocol with simulated UDP loss
def main():
    rule("Lab Two Local Demo")
    print("Three In Process Signers Run The Round Robin Protocol")
    print(
        f"Network Drop Rate = {int(LOSS_RATE * 100)}% Per Send Retry Up To Three Times"
    )
    print(f"Wall Clock Budget = {GROUP_BUDGET_SECONDS:.0f}s Across All Three Rounds")
    print()

    section("Key Generation")
    keys = [default_eccrypto.generate_key("curve25519") for _ in range(3)]
    pubs = [k.pub().key_to_bin() for k in keys]
    rows(
        [
            ("Member 1 Key", f"...{pubs[0][-8:].hex()}"),
            ("Member 2 Key", f"...{pubs[1][-8:].hex()}"),
            ("Member 3 Key", f"...{pubs[2][-8:].hex()}"),
        ]
    )

    section("Registration")
    server = MockServer(pubs)
    rows([("Group ID", server.group_id), ("Members", 3)])

    success = True
    for round_num in (1, 2, 3):
        ok = run_round(server, keys, pubs, round_num)
        if not ok:
            success = False
            break
        print()

    elapsed = time.time() - server.start_time
    divider()
    rows(
        [
            ("Rounds Completed", f"{len(server.submitters_seen)}/3"),
            ("Distinct Submitters", len(server.submitters_seen)),
            ("Elapsed", f"{elapsed:.2f}s"),
            ("Budget", f"{GROUP_BUDGET_SECONDS:.2f}s"),
            ("Within Budget", elapsed < GROUP_BUDGET_SECONDS),
            ("Success", success),
        ]
    )
    assert success
    assert len(server.submitters_seen) == 3
    assert elapsed < GROUP_BUDGET_SECONDS
    rule("Lab Two Demo Passed")


if __name__ == "__main__":
    main()

import os
import time
from struct import Struct
from hashlib import sha256
from multiprocessing import Event, Queue, Process

from labs.one.miner import EMAIL, PREFIX, GITHUB_URL, validate_nonce
from common.banner import rule, rows, divider, section

# precompiled packer matching the production worker for the 8 byte nonce
_NONCE_STRUCT = Struct(">q")
# difficulties walked sequentially in the single thread showcase
SCALE_DIFFICULTIES = (20, 22, 24)
# difficulty for the parallel showcase chosen so eight cores finish in a few seconds
PARALLEL_DIFFICULTY = 26


# single thread search that returns the first nonce satisfying difficulty plus stats
def search_single(difficulty: int):
    base = sha256(PREFIX)
    nonce = 0
    start = time.time()
    while True:
        h = base.copy()
        h.update(_NONCE_STRUCT.pack(nonce))
        digest = h.digest()
        if validate_nonce(digest, difficulty):
            return nonce, digest, nonce + 1, time.time() - start
        nonce += 1


# subprocess worker body mining a single stride at the requested difficulty
def parallel_worker(worker_id, num_workers, difficulty, result_queue, stop_event):
    base = sha256(PREFIX)
    nonce = worker_id
    attempts = 0
    while True:
        h = base.copy()
        h.update(_NONCE_STRUCT.pack(nonce))
        digest = h.digest()
        attempts += 1
        if validate_nonce(digest, difficulty):
            result_queue.put((worker_id, nonce, digest, attempts))
            stop_event.set()
            return
        nonce += num_workers
        if nonce & 0x3FFF == 0 and stop_event.is_set():
            return


# parallel orchestrator that spawns one worker per core and times the winner
def search_parallel(difficulty: int):
    num_workers = os.cpu_count() or 1
    result_queue, stop_event = Queue(), Event()
    workers = [
        Process(
            target=parallel_worker,
            args=(i, num_workers, difficulty, result_queue, stop_event),
        )
        for i in range(num_workers)
    ]
    start = time.time()
    for w in workers:
        w.start()
    winner_id, nonce, digest, attempts = result_queue.get()
    elapsed = time.time() - start
    for w in workers:
        w.terminate()
    for w in workers:
        w.join()
    return winner_id, num_workers, nonce, digest, attempts, elapsed


# entry point that walks single thread scaling then parallel speed up
def main():
    rule("Lab One Local Demo")
    print("Real Proof Of Work Search Over Email Plus Github Url Plus Nonce")
    print("Spec Difficulty Is 28 Bits Demo Walks Lower Bits And One Parallel Run")
    print()

    section("Hash Preimage")
    rows(
        [
            ("Email", EMAIL),
            ("Github Url", GITHUB_URL),
            ("Prefix Length", f"{len(PREFIX)} bytes"),
            ("Prefix Bytes", f"{PREFIX!r}"),
        ]
    )

    section("Single Thread Scaling")
    print("Each Step Doubles Required Work So Time Roughly Quadruples Per Two Bits")
    print()
    last_digest = b""
    last_difficulty = 0
    for difficulty in SCALE_DIFFICULTIES:
        nonce, digest, attempts, elapsed = search_single(difficulty)
        print(
            f"  Difficulty {difficulty:>2}  nonce={nonce:>10}  "
            f"attempts={attempts:>10}  time={elapsed * 1000:>6.0f}ms  "
            f"digest={digest[:6].hex()}..."
        )
        last_digest, last_difficulty = digest, difficulty

    section("Parallel Search At Higher Difficulty")
    print(f"Spawning One Subprocess Per CPU Core Targeting {PARALLEL_DIFFICULTY} Bits")
    winner_id, workers, nonce, digest, attempts, elapsed = search_parallel(
        PARALLEL_DIFFICULTY
    )
    rows(
        [
            ("Workers", workers),
            ("Winning Worker", winner_id),
            ("Winning Nonce", nonce),
            ("Worker Attempts", attempts),
            ("Digest", digest.hex()),
            ("Wall Time", f"{elapsed:.2f}s"),
        ]
    )

    section("Independent Verification")
    h = sha256(PREFIX)
    h.update(_NONCE_STRUCT.pack(nonce))
    recomputed = h.digest()
    rows(
        [
            ("Recomputed Hash", recomputed.hex()),
            ("Matches Mined", recomputed == digest),
            ("Zero Bits Pass", validate_nonce(recomputed, PARALLEL_DIFFICULTY)),
            ("Last Single Thread Difficulty", last_difficulty),
            ("Single Thread Verifies", validate_nonce(last_digest, last_difficulty)),
        ]
    )
    divider()
    assert recomputed == digest
    assert validate_nonce(recomputed, PARALLEL_DIFFICULTY)
    assert validate_nonce(last_digest, last_difficulty)
    rule("Lab One Demo Passed")


if __name__ == "__main__":
    main()

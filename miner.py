import os
import time
from struct import Struct
from hashlib import sha256
from multiprocessing import Event, Queue, Process

DIFFICULTY = 28
EMAIL = "acpatil@tudelft.nl"
GITHUB_URL = "https://github.com/outofaditya/blockchain-labs"
PREFIX = EMAIL.encode() + b"\n" + GITHUB_URL.encode() + b"\n"

# pre-compiled for the mining hot path
_NONCE_STRUCT = Struct(">q")


def validate_nonce(digest: bytes, bits: int) -> bool:
    full, rem = divmod(bits, 8)
    if any(digest[:full]):
        return False
    return not rem or digest[full] < (1 << (8 - rem))


def worker(worker_id: int, num_workers: int, result_queue, stop_event):
    base = sha256(PREFIX)
    nonce = worker_id
    while True:
        h = base.copy()
        h.update(_NONCE_STRUCT.pack(nonce))
        digest = h.digest()
        if validate_nonce(digest, DIFFICULTY):
            result_queue.put((nonce, digest))
            stop_event.set()
            return
        nonce += num_workers
        # cheap power-of-2 check fires every 16384 iterations
        if nonce & 0x3FFF == 0 and stop_event.is_set():
            return


def mine():
    num_workers = os.cpu_count() or 1
    print(
        f"{'=' * 80}\nPROOF-OF-WORK MINER PROGRAM\n{'=' * 80}\n"
        f"{'Email':<15}: {EMAIL}\n"
        f"{'GitHub URL':<15}: {GITHUB_URL}\n"
        f"{'Workers':<15}: {num_workers}\n"
        f"{'Difficulty':<15}: {DIFFICULTY} Leading Zero Bits\n"
        f"{'-' * 80}\nMINING STARTED\n{'-' * 80}"
    )

    result_queue, stop_event = Queue(), Event()
    workers = [
        Process(target=worker, args=(i, num_workers, result_queue, stop_event))
        for i in range(num_workers)
    ]
    start = time.time()
    for w in workers:
        w.start()

    nonce, digest = result_queue.get()
    elapsed = time.time() - start

    print(
        f"{'Nonce':<15}: {nonce}\n"
        f"{'Digest Value':<15}: {digest.hex()}\n"
        f"{'Time Elapsed':<15}: {elapsed:.2f} seconds\n{'=' * 80}"
    )

    for w in workers:
        w.terminate()
    for w in workers:
        w.join()

    return nonce, digest


if __name__ == "__main__":
    mine()

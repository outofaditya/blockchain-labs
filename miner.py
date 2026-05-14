import os
import time
import struct
import hashlib
import multiprocessing as mp

# constants
DIFFICULTY = 28
EMAIL = "acpatil@tudelft.nl"
GITHUB_URL = "https://github.com/outofaditya/blockchain-labs"

# binary optimization
prefix = EMAIL.encode("utf-8") + b"\n" + GITHUB_URL.encode("utf-8") + b"\n"


# nonce validation function
def validate_nonce(digest: bytes, bits: int) -> bool:
    # perform byte-wise check for the number of leading zeros
    full_bytes, remainder = divmod(bits, 8)
    # check each byte in the digest
    for b in digest[:full_bytes]:
        if b != 0:
            return False
    # check the remaining bits if any
    if remainder:
        return digest[full_bytes] < (1 << (8 - remainder))
    return True


# the worker function
def worker(worker_id: int, num_workers: int, result_queue, stop_event):
    base = hashlib.sha256(prefix)

    # partition the nonce range as i then i+N and so on
    nonce = worker_id

    while True:
        h = base.copy()
        h.update(struct.pack(">q", nonce))
        digest = h.digest()
        if validate_nonce(digest, DIFFICULTY):
            result_queue.put((nonce, digest))
            stop_event.set()
            return
        nonce += num_workers
        # cheap power-of-2 check; fires every 16384 iterations
        if nonce & 0x3FFF == 0 and stop_event.is_set():
            return


# the mining loop
def mine():
    # get the available core count
    num_workers = os.cpu_count() or 1

    # general print statements
    print("=" * 80)
    print("PROOF-OF-WORK MINER PROGRAM")
    print("=" * 80)

    print(f"{'Email':<15}: {EMAIL}")
    print(f"{'GitHub URL':<15}: {GITHUB_URL}")
    print(f"{'Workers':<15}: {num_workers}")
    print(f"{'Difficulty':<15}: {DIFFICULTY} Leading Zero Bits")

    print("-" * 80)
    print("MINING STARTED")
    print("-" * 80)

    # set the structures for workers
    result_queue = mp.Queue()
    stop_event = mp.Event()
    start = time.time()

    workers = [
        mp.Process(target=worker, args=(i, num_workers, result_queue, stop_event))
        for i in range(num_workers)
    ]

    # start the worker processes
    for w in workers:
        w.start()

    # wait for the first result
    nonce, digest = result_queue.get()

    elapsed = time.time() - start

    print(f"{'Nonce':<15}: {nonce}")
    print(f"{'Digest Value':<15}: {digest.hex()}")
    print(f"{'Time Elapsed':<15}: {elapsed:.2f} seconds")

    print("=" * 80)

    for w in workers:
        w.terminate()
    for w in workers:
        w.join()

    return nonce, digest


if __name__ == "__main__":
    mine()

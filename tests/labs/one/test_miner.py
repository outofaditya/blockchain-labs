from hashlib import sha256

from labs.one.miner import EMAIL, PREFIX, worker, DIFFICULTY, GITHUB_URL, validate_nonce


# precomputed prefix is exactly email plus newline plus url plus newline in UTF 8
def test_prefix_construction():
    expected = EMAIL.encode() + b"\n" + GITHUB_URL.encode() + b"\n"
    assert PREFIX == expected


# difficulty constant matches the lab 1 spec
def test_difficulty_matches_spec():
    assert DIFFICULTY == 28


# leading zero validator honors both full bytes and remainder bits
def test_validate_nonce_byte_boundary():
    assert validate_nonce(b"\x00\x00\xff" + b"\x00" * 29, 16)
    assert not validate_nonce(b"\x00\x00\xff" + b"\x00" * 29, 17)
    assert validate_nonce(b"\x00\x0f" + b"\x00" * 30, 12)
    assert not validate_nonce(b"\x00\x10" + b"\x00" * 30, 12)


# an all zero digest satisfies any difficulty
def test_validate_nonce_full_zero_passes_any_difficulty():
    assert validate_nonce(b"\x00" * 32, 256)


# worker exits cleanly when stop_event is already set on entry
def test_worker_terminates_when_stop_event_fires_before_finding():
    from multiprocessing import Event, Queue

    queue = Queue()
    stop = Event()
    stop.set()
    worker(0, 1, queue, stop)
    assert queue.empty()


# at difficulty 8 a valid nonce exists within the first 1024 attempts
def test_known_nonce_satisfies_low_difficulty():
    for nonce in range(1024):
        h = sha256(PREFIX)
        h.update(nonce.to_bytes(8, "big", signed=True))
        if validate_nonce(h.digest(), 8):
            return
    raise AssertionError("Expected a difficulty 8 nonce within 1024 attempts")

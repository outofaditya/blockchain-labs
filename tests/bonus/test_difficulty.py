from bonus.difficulty import (
    retarget,
    MAX_FUTURE_DRIFT,
    is_valid_timestamp,
    median_past_timestamp,
)


# median of an empty list returns zero so any candidate passes the past gate
def test_median_past_timestamp_empty_returns_zero():
    assert median_past_timestamp([]) == 0


# median of last eleven entries is the central value
def test_median_past_timestamp_returns_middle_of_window():
    ts = list(range(1, 14))
    assert median_past_timestamp(ts) == 8


# candidate above the past median and within drift passes
def test_is_valid_timestamp_accepts_normal_candidate():
    prev = [100, 110, 120, 130, 140]
    assert is_valid_timestamp(200, prev, now=300)


# candidate at or below the past median fails the past gate
def test_is_valid_timestamp_rejects_past_manipulation():
    prev = [100, 110, 120, 130, 140]
    assert not is_valid_timestamp(120, prev, now=300)


# candidate beyond now plus drift fails the future gate
def test_is_valid_timestamp_rejects_far_future_candidate():
    prev = [100, 200]
    assert not is_valid_timestamp(1000, prev, now=200)
    assert is_valid_timestamp(200 + MAX_FUTURE_DRIFT, prev, now=200)


# pre boundary retarget returns the current difficulty unchanged
def test_retarget_skips_pre_boundary_heights():
    timestamps = list(range(10))
    assert retarget(7, timestamps, current_difficulty=18) == 18


# eight blocks taking thirty two seconds against expected sixteen drops difficulty by one
def test_retarget_slow_network_drops_difficulty():
    timestamps = [0, 4, 8, 12, 16, 20, 24, 28, 32]
    assert retarget(height=8, timestamps=timestamps, current_difficulty=18) == 17


# eight blocks in eight seconds against expected sixteen raises difficulty by one
def test_retarget_fast_network_raises_difficulty():
    timestamps = [0, 1, 2, 3, 4, 5, 6, 7, 8]
    assert retarget(height=8, timestamps=timestamps, current_difficulty=18) == 19


# extreme speedup clamps at four times so difficulty grows by exactly two bits
def test_retarget_clamps_extreme_speedup():
    timestamps = [0, 0, 0, 0, 0, 0, 0, 0, 1]
    assert retarget(height=8, timestamps=timestamps, current_difficulty=18) == 20


# difficulty floor stops further drops once it hits the minimum
def test_retarget_respects_floor():
    very_slow = [0, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000]
    assert retarget(8, very_slow, current_difficulty=10) == 8
    assert retarget(8, very_slow, current_difficulty=9) == 8


# difficulty ceiling caps further raises once it hits the maximum
def test_retarget_respects_ceiling():
    very_fast = [0, 0, 0, 0, 0, 0, 0, 0, 1]
    assert retarget(8, very_fast, current_difficulty=31) == 32
    assert retarget(8, very_fast, current_difficulty=32) == 32

import time

from bonus.difficulty import (
    retarget,
    MAX_ADJUST_FACTOR,
    RETARGET_INTERVAL,
    TARGET_BLOCK_SECONDS,
)
from labs.three.chain import mine_block
from common.banner import rule, rows, divider, section

# dummy hashes used as the static portion of the mined header
_ZERO = b"\x00" * 32
# floor sleep keeps the per block cadence visible even when mining is cheap
_FLOOR_SLEEP = 0.15
# how many blocks each scenario runs for chosen to span multiple retarget windows
_BLOCKS = 32


# runs one scenario by mining real blocks while feeding a synthesized network cadence
def simulate(label, cadence, start_difficulty=18):
    section(label)
    timestamps = [0]
    difficulty = start_difficulty
    print(f"  Start Difficulty = {start_difficulty}")
    print(f"  Block Count      = {_BLOCKS}")
    divider()
    for h in range(1, _BLOCKS + 1):
        # real mining at the current difficulty so demo time correlates with retarget output
        start = time.time()
        mine_block(_ZERO, _ZERO, difficulty, h)
        mining_time = time.time() - start

        # synthesized timestamp drives the retarget regardless of real wall clock
        gap = cadence(h - 1)
        timestamps.append(timestamps[-1] + gap)

        print(
            f"  Block {h:>2}  difficulty={difficulty:>2}  "
            f"gap={gap}s  mined={mining_time * 1000:>5.0f}ms"
        )

        # retarget event prints when the boundary is crossed showing span and ratio
        next_difficulty = retarget(h, timestamps, difficulty)
        if h % RETARGET_INTERVAL == 0 and h >= RETARGET_INTERVAL:
            span = timestamps[-1] - timestamps[-(RETARGET_INTERVAL + 1)]
            expected = RETARGET_INTERVAL * TARGET_BLOCK_SECONDS
            ratio = expected / max(1, span)
            clamped = max(1 / MAX_ADJUST_FACTOR, min(MAX_ADJUST_FACTOR, ratio))
            print(
                f"           RETARGET span={span}s expected={expected}s "
                f"ratio={ratio:.2f} clamped={clamped:.2f} "
                f"difficulty={difficulty}->{next_difficulty}"
            )
        difficulty = next_difficulty
        time.sleep(_FLOOR_SLEEP)
    print(f"  Final Difficulty = {difficulty}")
    return difficulty


# entry point that walks four contrasting network conditions
def main():
    rule("Bonus Two Adaptive Difficulty")
    print(f"Target Block Time: {TARGET_BLOCK_SECONDS}s")
    print(f"Retarget Interval: {RETARGET_INTERVAL} Blocks")
    print(f"Max Adjust Factor: {MAX_ADJUST_FACTOR}x")
    print(f"Blocks Per Scenario: {_BLOCKS}")
    print()

    # scenario A blocks land twice as fast as target hash power surges
    final_surge = simulate("Scenario A Hash Power Surges (Gap 1s)", lambda h: 1)
    print()
    # scenario B blocks land four times slower than target hash power drops
    final_drought = simulate("Scenario B Hash Power Drops (Gap 8s)", lambda h: 8)
    print()
    # scenario C blocks land at the target cadence steady state
    final_steady = simulate("Scenario C Steady State (Gap 2s)", lambda h: 2)
    print()

    # scenario D abrupt regime change to test responsiveness
    def regime_shift(idx):
        return 1 if idx < _BLOCKS // 2 else 6

    final_abrupt = simulate("Scenario D Abrupt Regime Change", regime_shift)

    divider()
    rows(
        [
            ("Surge End", final_surge),
            ("Drought End", final_drought),
            ("Steady End", final_steady),
            ("Abrupt Shift End", final_abrupt),
            ("Surge Raised", final_surge > 18),
            ("Drought Dropped", final_drought < 18),
            ("Steady Unchanged", final_steady == 18),
            ("Abrupt Returned Toward Baseline", final_abrupt < final_surge),
        ]
    )
    assert final_surge > 18
    assert final_drought < 18
    assert final_steady == 18
    assert final_abrupt < final_surge
    rule("Bonus Two Demo Passed")


if __name__ == "__main__":
    main()

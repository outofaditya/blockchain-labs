from bonus.difficulty import (
    RETARGET_INTERVAL,
    TARGET_BLOCK_SECONDS,
    retarget,
)
from common.banner import rule, rows, divider, section


# simulates one network condition by feeding timestamps with a fixed inter block gap
def simulate(label, gap_seconds, blocks=24, start_difficulty=18):
    section(label)
    timestamps = [0]
    difficulty = start_difficulty
    snapshot = []
    for h in range(1, blocks + 1):
        # next block lands gap_seconds after the previous one
        timestamps.append(timestamps[-1] + gap_seconds)
        snapshot.append((h, difficulty))
        # network retargets at the boundary if applicable
        difficulty = retarget(h, timestamps, difficulty)
    # only print one row per retarget boundary for readability
    rows(
        [
            (f"After Block {h}", f"Difficulty {d}")
            for h, d in snapshot
            if h % RETARGET_INTERVAL == 0
        ]
    )
    return difficulty


# entry point that walks three scenarios end to end
def main():
    rule("Bonus Two Adaptive Difficulty")
    print(f"Target Block Time: {TARGET_BLOCK_SECONDS}s")
    print(f"Retarget Interval: {RETARGET_INTERVAL} Blocks")
    print("Start Difficulty:  18 bits")
    print()

    # surge fires when blocks land twice as fast as target
    final_surge = simulate("Scenario A Hash Power Surges", gap_seconds=1)
    print()
    # drought fires when blocks land four times slower than target
    final_drought = simulate("Scenario B Hash Power Drops", gap_seconds=8)
    print()
    # steady fires when network meets the target exactly
    final_steady = simulate("Scenario C Steady State", gap_seconds=TARGET_BLOCK_SECONDS)

    divider()
    rows(
        [
            ("Final After Surge", final_surge),
            ("Final After Drought", final_drought),
            ("Final After Steady", final_steady),
            ("Surge Raised", final_surge > 18),
            ("Drought Dropped", final_drought < 18),
            ("Steady Unchanged", final_steady == 18),
        ]
    )
    assert final_surge > 18 and final_drought < 18 and final_steady == 18
    rule("Bonus Two Demo Passed")


if __name__ == "__main__":
    main()

from common.banner import rule, rows, divider, section


# rule with a title prints the title between two equals lines
def test_rule_with_title(capsys):
    rule("HELLO")
    out = capsys.readouterr().out
    assert "HELLO" in out
    assert out.count("=" * 80) == 2


# rule without a title prints a single equals line
def test_rule_without_title(capsys):
    rule()
    out = capsys.readouterr().out
    assert out.count("=" * 80) == 1


# section wraps the title between two dashed lines
def test_section_wraps_title_in_dashes(capsys):
    section("MID")
    out = capsys.readouterr().out
    assert "MID" in out
    assert out.count("-" * 80) == 2


# divider prints a single dashed line
def test_divider_prints_dashed_line(capsys):
    divider()
    out = capsys.readouterr().out
    assert out.strip() == "-" * 80


# rows aligns each label to the configured width followed by a colon
def test_rows_aligns_labels(capsys):
    rows([("Foo", 1), ("Bar", "x")], label_width=10)
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("Foo")
    assert ":" in out[0]
    assert out[1].startswith("Bar")

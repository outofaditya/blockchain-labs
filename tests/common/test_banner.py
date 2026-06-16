from common.banner import divider, rows, rule, section


def test_rule_with_title(capsys):
    rule("HELLO")
    out = capsys.readouterr().out
    assert "HELLO" in out
    assert out.count("=" * 80) == 2


def test_rule_without_title(capsys):
    rule()
    out = capsys.readouterr().out
    assert out.count("=" * 80) == 1


def test_section_wraps_title_in_dashes(capsys):
    section("MID")
    out = capsys.readouterr().out
    assert "MID" in out
    assert out.count("-" * 80) == 2


def test_divider_prints_dashed_line(capsys):
    divider()
    out = capsys.readouterr().out
    assert out.strip() == "-" * 80


def test_rows_aligns_labels(capsys):
    rows([("Foo", 1), ("Bar", "x")], label_width=10)
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("Foo")
    assert ":" in out[0]
    assert out[1].startswith("Bar")

_WIDTH = 80


def rule(title: str | None = None) -> None:
    print("=" * _WIDTH)
    if title:
        print(title)
        print("=" * _WIDTH)


def section(title: str) -> None:
    print("-" * _WIDTH)
    print(title)
    print("-" * _WIDTH)


def divider() -> None:
    print("-" * _WIDTH)


def rows(items, label_width: int = 15) -> None:
    for label, value in items:
        print(f"{label:<{label_width}}: {value}")

# shared output width used by every banner helper
_WIDTH = 80


# prints an equals divider with an optional title between two equals lines
def rule(title: str | None = None) -> None:
    print("=" * _WIDTH)
    if title:
        print(title)
        print("=" * _WIDTH)


# prints a dashed divider around a title
def section(title: str) -> None:
    print("-" * _WIDTH)
    print(title)
    print("-" * _WIDTH)


# prints a single dashed line
def divider() -> None:
    print("-" * _WIDTH)


# prints aligned key value rows padded to label_width
def rows(items, label_width: int = 15) -> None:
    for label, value in items:
        print(f"{label:<{label_width}}: {value}")

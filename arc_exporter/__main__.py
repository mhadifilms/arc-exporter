"""Allow ``python -m arc_exporter`` as an entry point."""

from __future__ import annotations

from arc_exporter.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()

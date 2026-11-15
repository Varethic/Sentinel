from __future__ import annotations
import sys
from src.run import _main as _runmain

class Cli:
    def _start(self, args: list[str] | None = None) -> None:
        _runmain(list(sys.argv[1:]) if args is None else args)

_cli = Cli()

def _main(argv: list[str] | None = None) -> None:
    _cli._start(argv)

if __name__ == "__main__":
    _main()

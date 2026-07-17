import argparse
import sys

from .collector import collect
from .config import load_targets
from .diff import compare_all
from .report import build_report, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="driftwatch", description="Compare SQL Server schemas.")
    parser.add_argument("--config", required=True, help="JSON configuration with at least two targets")
    parser.add_argument("--output", help="write JSON report to this path")
    args = parser.parse_args(argv)
    try:
        targets = load_targets(args.config)
        inventories = [collect(target) for target in targets]
        findings = compare_all(inventories)
        write_json(build_report(inventories, findings), args.output)
        return 2 if findings else 0
    except (OSError, ValueError) as exc:
        print(f"driftwatch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

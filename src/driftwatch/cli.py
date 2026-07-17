import argparse
import sys

from .collector import collect
from .config import apply_cli_credentials, load_targets
from .diff import compare_all
from .report import build_report, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="driftwatch", description="Compare SQL Server schemas.")
    parser.add_argument("--config", required=True, help="JSON configuration with at least two targets")
    parser.add_argument("--output", help="write JSON report to this path")
    parser.add_argument("--username", help="SQL Server login used for every configured target")
    password = parser.add_mutually_exclusive_group()
    password.add_argument("--password", help="SQL Server password (visible to the process list)")
    password.add_argument("--password-stdin", action="store_true", help="read the SQL Server password from stdin")
    args = parser.parse_args(argv)
    try:
        if args.password_stdin:
            if sys.stdin.isatty():
                raise ValueError("--password-stdin requires a piped password")
            password_value = sys.stdin.readline().rstrip("\r\n")
        else:
            password_value = args.password
        targets = apply_cli_credentials(load_targets(args.config), args.username, password_value)
        inventories = [collect(target) for target in targets]
        findings = compare_all(inventories)
        write_json(build_report(inventories, findings), args.output)
        return 2 if findings else 0
    except (OSError, ValueError) as exc:
        print(f"driftwatch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

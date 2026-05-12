"""Count SARIF alerts by severity level."""

from __future__ import annotations

import json
import sys


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: count-sarif-alerts.py <sarif-file>", file=sys.stderr)
        sys.exit(1)

    sarif_file = sys.argv[1]

    try:
        with open(sarif_file) as f:
            sarif = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("0 0 0 0")
        return

    results = sarif.get("runs", [{}])[0].get("results", [])
    high = medium = low = 0
    for r in results:
        level = r.get("level", "note")
        if level == "error":
            high += 1
        elif level == "warning":
            medium += 1
        elif level == "note":
            low += 1

    total = len(results)
    print(f"{total} {high} {medium} {low}")


if __name__ == "__main__":
    main()

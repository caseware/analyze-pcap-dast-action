"""Generate a ZAP Automation Framework plan YAML for passive scanning."""

from __future__ import annotations

import json
import os
import sys


def main() -> None:
    har_file = os.environ.get("HAR_FILE", "")
    work_dir = os.environ.get("WORK_DIR", "")
    target_url = os.environ.get("TARGET_URL", "")

    if not work_dir:
        print("WORK_DIR is required", file=sys.stderr)
        sys.exit(1)

    # Derive target from HAR if not set
    if not target_url and har_file:
        with open(har_file) as f:
            har = json.load(f)
        entries = har.get("log", {}).get("entries", [])
        if entries:
            from urllib.parse import urlparse
            url = entries[0]["request"]["url"]
            p = urlparse(url)
            target_url = f"{p.scheme}://{p.netloc}"
        else:
            target_url = "https://localhost"

    print(f"Target: {target_url}")

    plan = {
        "env": {
            "contexts": [{"name": "passive-dast", "urls": [target_url]}],
            "parameters": {
                "failOnError": True,
                "failOnWarning": False,
                "progressToStdout": True,
            },
        },
        "jobs": [
            {
                "type": "import",
                "parameters": {"type": "har", "fileName": "/zap/wrk/input.har"},
            },
            {
                "type": "passiveScan-config",
                "parameters": {
                    "maxAlertsPerRule": 10,
                    "scanOnlyInScope": False,
                    "maxBodySizeInBytesToScan": 0,
                },
            },
            {
                "type": "passiveScan-wait",
                "parameters": {"maxDuration": 300},
            },
            {
                "type": "report",
                "parameters": {
                    "template": "sarif-json",
                    "reportDir": "/zap/wrk",
                    "reportFile": "results",
                    "reportTitle": "DAST Passive Scan",
                },
            },
        ],
    }

    plan_path = os.path.join(work_dir, "zap-plan.yaml")

    try:
        import yaml
        with open(plan_path, "w") as f:
            yaml.dump(plan, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        with open(plan_path, "w") as f:
            json.dump(plan, f, indent=2)

    print(f"Wrote ZAP plan to {plan_path}")
    print(f"target-url={target_url}")


if __name__ == "__main__":
    main()

"""Fix SARIF URIs for GitHub Code Scanning compatibility.

ZAP produces SARIF with https:// URIs pointing to scanned web pages.
GitHub Code Scanning requires relative file paths (not web URLs).
This script converts web URIs to synthetic relative paths so the SARIF
can be uploaded without errors.
"""

from __future__ import annotations

import json
import sys
from urllib.parse import urlparse


def fix_sarif(sarif_path: str) -> None:
    with open(sarif_path) as f:
        sarif = json.load(f)

    for run in sarif.get("runs", []):
        # Fix artifact locations
        for artifact in run.get("artifacts", []):
            loc = artifact.get("location", {})
            uri = loc.get("uri", "")
            if uri.startswith("http://") or uri.startswith("https://"):
                loc["uri"] = _web_uri_to_path(uri)

        # Fix result locations
        for result in run.get("results", []):
            for location in result.get("locations", []):
                phys = location.get("physicalLocation", {})
                artifact_loc = phys.get("artifactLocation", {})
                uri = artifact_loc.get("uri", "")
                if uri.startswith("http://") or uri.startswith("https://"):
                    artifact_loc["uri"] = _web_uri_to_path(uri)

            # Fix related locations
            for related in result.get("relatedLocations", []):
                phys = related.get("physicalLocation", {})
                artifact_loc = phys.get("artifactLocation", {})
                uri = artifact_loc.get("uri", "")
                if uri.startswith("http://") or uri.startswith("https://"):
                    artifact_loc["uri"] = _web_uri_to_path(uri)

    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)


def _web_uri_to_path(uri: str) -> str:
    parsed = urlparse(uri)
    host = parsed.netloc or "unknown"
    path = parsed.path.strip("/") or "index"
    return f"dast-findings/{host}/{path}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: fix-sarif-uris.py <sarif-file>", file=sys.stderr)
        sys.exit(1)
    fix_sarif(sys.argv[1])

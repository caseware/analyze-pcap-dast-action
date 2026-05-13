"""Extract basic statistics from a Burp Suite XML site map.

Outputs a JSON summary with URL count, unique hosts, HTTP methods,
parameter counts, and response status code distribution.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def extract_stats(burp_xml_path: str) -> dict:
    tree = ET.parse(burp_xml_path)
    root = tree.getroot()

    items = root.findall("item")
    url_count = len(items)

    hosts: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    status_codes: Counter[str] = Counter()
    extensions: Counter[str] = Counter()
    total_params = 0
    urls_with_params = 0

    for item in items:
        host_el = item.find("host")
        if host_el is not None and host_el.text:
            hosts[host_el.text] += 1

        method_el = item.find("method")
        if method_el is not None and method_el.text:
            methods[method_el.text] += 1

        status_el = item.find("status")
        if status_el is not None and status_el.text:
            status_codes[status_el.text] += 1

        ext_el = item.find("extension")
        if ext_el is not None and ext_el.text:
            extensions[ext_el.text] += 1

        url_el = item.find("url")
        if url_el is not None and url_el.text:
            parsed = urlparse(url_el.text)
            params = parse_qs(parsed.query)
            param_count = len(params)
            if param_count > 0:
                urls_with_params += 1
                total_params += param_count

    return {
        "url_count": url_count,
        "unique_hosts": len(hosts),
        "hosts": dict(hosts.most_common()),
        "methods": dict(methods.most_common()),
        "status_codes": dict(status_codes.most_common()),
        "total_query_params": total_params,
        "urls_with_params": urls_with_params,
        "extensions": dict(extensions.most_common(10)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract statistics from Burp Suite XML site map"
    )
    parser.add_argument("burp_xml", help="Path to Burp XML site map file")
    parser.add_argument(
        "--output", "-o", help="Write JSON to file instead of stdout"
    )
    args = parser.parse_args()

    path = Path(args.burp_xml)
    if not path.exists():
        print(f"::error::Burp XML file not found: {path}", file=sys.stderr)
        sys.exit(1)

    stats = extract_stats(str(path))

    output = json.dumps(stats, indent=2)
    if args.output:
        Path(args.output).write_text(output + "\n")
        print(f"Stats written to {args.output}")
    else:
        print(output)

    print(f"::notice::Burp XML: {stats['url_count']} URLs, "
          f"{stats['unique_hosts']} hosts, "
          f"{stats['total_query_params']} query params")


if __name__ == "__main__":
    main()

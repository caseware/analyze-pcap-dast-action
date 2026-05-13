"""Convert mitmproxy flow files to DAST-compatible site maps.

Outputs:
  - sitemap.har   (HAR 1.2 — ZAP, Burp Suite, Rapid7, Chrome DevTools)
  - urls.txt      (one URL per line — ZAP import, Rapid7 bulk add)
  - sitemap-burp.xml (Burp Suite native XML site map)
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from xml.dom import minidom

from mitmproxy import io as mio
from mitmproxy.http import HTTPFlow


def _read_version() -> str:
    """Read the version from the VERSION file at the repo root."""
    version_file = Path(__file__).resolve().parent.parent / "VERSION"
    if version_file.is_file():
        return version_file.read_text().strip()
    return "0.0.0"


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _glob_match(value: str, patterns: list[str]) -> bool:
    lo = value.lower()
    return any(fnmatch.fnmatch(lo, p.lower()) for p in patterns)


def _har_cookies(cookies) -> list[dict]:
    """Convert mitmproxy cookies to HAR cookie format.

    Request cookies: MultiDictView[str, str] — (name, value)
    Response cookies: MultiDictView[str, tuple[str, MultiDict]] — (name, (value, attrs))
    """
    result: list[dict] = []
    for name, val in cookies.items(multi=True):
        if isinstance(val, tuple):
            result.append({"name": name, "value": val[0]})
        else:
            result.append({"name": name, "value": str(val)})
    return result


def _should_include(
    flow: HTTPFlow,
    *,
    domain_allow: list[str],
    domain_deny: list[str],
    status_codes: list[int],
    methods: list[str],
) -> bool:
    host = flow.request.pretty_host
    if domain_allow and not _glob_match(host, domain_allow):
        return False
    if domain_deny and _glob_match(host, domain_deny):
        return False
    if status_codes and (not flow.response or flow.response.status_code not in status_codes):
        return False
    if methods and flow.request.method.upper() not in methods:
        return False
    return True


def _flow_to_har_entry(flow: HTTPFlow) -> dict:
    req = flow.request
    resp = flow.response

    ts_start = flow.timestamp_start or 0
    started = datetime.fromtimestamp(
        ts_start, tz=timezone.utc
    ).isoformat()

    har_request = {
        "method": req.method,
        "url": req.pretty_url,
        "httpVersion": req.http_version,
        "cookies": _har_cookies(req.cookies),
        "headers": [
            {"name": k, "value": v}
            for k, v in req.headers.items(multi=True)
        ],
        "queryString": [
            {"name": k, "value": v}
            for k, v in req.query.items(multi=True)
        ],
        "headersSize": len(str(req.headers)),
        "bodySize": len(req.content) if req.content else 0,
    }

    if req.content:
        ct = req.headers.get("content-type", "")
        if ct.startswith("application/x-www-form-urlencoded"):
            har_request["postData"] = {
                "mimeType": ct,
                "params": [
                    {"name": k, "value": v}
                    for k, v in req.urlencoded_form.items(multi=True)
                ],
                "text": req.content.decode("utf-8", errors="replace"),
            }
        else:
            har_request["postData"] = {
                "mimeType": ct,
                "text": req.content.decode("utf-8", errors="replace"),
            }

    har_response: dict = {
        "status": 0,
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": [],
        "content": {"size": 0, "mimeType": ""},
        "redirectURL": "",
        "headersSize": 0,
        "bodySize": 0,
    }

    if resp:
        har_response = {
            "status": resp.status_code,
            "statusText": resp.reason or "",
            "httpVersion": resp.http_version,
            "cookies": _har_cookies(resp.cookies),
            "headers": [
                {"name": k, "value": v}
                for k, v in resp.headers.items(multi=True)
            ],
            "content": {
                "size": len(resp.content) if resp.content else 0,
                "mimeType": resp.headers.get("content-type", ""),
                "text": resp.content.decode("utf-8", errors="replace")
                if resp.content
                else "",
            },
            "redirectURL": resp.headers.get("location", ""),
            "headersSize": len(str(resp.headers)),
            "bodySize": len(resp.content) if resp.content else 0,
        }

    # HTTPFlow doesn't have timestamp_end; use response timestamp if available
    if resp and hasattr(flow, 'response') and hasattr(flow.response, 'timestamp_end'):
        time_ms = int((flow.response.timestamp_end - ts_start) * 1000)
    else:
        time_ms = 0

    return {
        "startedDateTime": started,
        "time": time_ms,
        "request": har_request,
        "response": har_response,
        "cache": {},
        "timings": {"send": 0, "wait": time_ms, "receive": 0},
    }


def _flow_to_burp_item(flow: HTTPFlow) -> ET.Element:
    req = flow.request
    resp = flow.response

    item = ET.Element("item")

    ET.SubElement(item, "time").text = datetime.fromtimestamp(
        flow.timestamp_start or 0, tz=timezone.utc
    ).strftime("%a %b %d %H:%M:%S UTC %Y")
    ET.SubElement(item, "url").text = req.pretty_url
    ET.SubElement(item, "host").text = req.pretty_host
    ET.SubElement(item, "port").text = str(req.port)
    ET.SubElement(item, "protocol").text = req.scheme
    ET.SubElement(item, "method").text = req.method
    ET.SubElement(item, "path").text = req.path
    ET.SubElement(item, "extension").text = (
        req.path.rsplit(".", 1)[-1][:10] if "." in req.path.split("?")[0] else ""
    )

    raw_req = req.method + " " + req.path + " " + req.http_version + "\r\n"
    for k, v in req.headers.items(multi=True):
        raw_req += k + ": " + v + "\r\n"
    raw_req += "\r\n"
    if req.content:
        raw_req += req.content.decode("utf-8", errors="replace")
    req_el = ET.SubElement(item, "request")
    req_el.set("base64", "true")
    req_el.text = base64.b64encode(raw_req.encode()).decode()

    ET.SubElement(item, "status").text = str(resp.status_code) if resp else "0"
    ET.SubElement(item, "responselength").text = str(
        len(resp.content) if resp and resp.content else 0
    )
    ET.SubElement(item, "mimetype").text = (
        resp.headers.get("content-type", "") if resp else ""
    )

    if resp:
        raw_resp = (
            resp.http_version + " " + str(resp.status_code) + " "
            + (resp.reason or "") + "\r\n"
        )
        for k, v in resp.headers.items(multi=True):
            raw_resp += k + ": " + v + "\r\n"
        raw_resp += "\r\n"
        if resp.content:
            raw_resp += resp.content.decode("utf-8", errors="replace")
        resp_el = ET.SubElement(item, "response")
        resp_el.set("base64", "true")
        resp_el.text = base64.b64encode(raw_resp.encode()).decode()
    else:
        ET.SubElement(item, "response")

    ET.SubElement(item, "comment")
    return item


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert mitmproxy flows to DAST site maps"
    )
    parser.add_argument("--flows-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--filter-domains", default="")
    parser.add_argument("--filter-exclude-domains", default="")
    parser.add_argument("--filter-status-codes", default="")
    parser.add_argument("--filter-methods", default="")
    args = parser.parse_args()

    flows_dir = Path(args.flows_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    domain_allow = _csv(args.filter_domains)
    domain_deny = _csv(args.filter_exclude_domains)
    status_codes = [int(s) for s in _csv(args.filter_status_codes)]
    methods = [m.upper() for m in _csv(args.filter_methods)]

    har_entries: list[dict] = []
    urls: set[str] = set()
    burp_items: list[ET.Element] = []

    flow_files = sorted(flows_dir.glob("*.flows"))
    if not flow_files:
        print("::warning::No mitmproxy flow files found in " + str(flows_dir))

    total = 0
    kept = 0
    for flow_file in flow_files:
        print(f"Processing {flow_file.name}")
        with open(flow_file, "rb") as f:
            reader = mio.FlowReader(f)
            for flow in reader.stream():
                if not isinstance(flow, HTTPFlow):
                    continue
                total += 1
                if not _should_include(
                    flow,
                    domain_allow=domain_allow,
                    domain_deny=domain_deny,
                    status_codes=status_codes,
                    methods=methods,
                ):
                    continue
                kept += 1
                har_entries.append(_flow_to_har_entry(flow))
                urls.add(flow.request.pretty_url)
                burp_items.append(_flow_to_burp_item(flow))

    print(f"Processed {total} flows, kept {kept}")

    # ── HAR ────────────────────────────────────────────────────────────
    har = {
        "log": {
            "version": "1.2",
            "creator": {
                "name": "analyze-pcap-dast-action",
                "version": _read_version(),
            },
            "entries": har_entries,
        }
    }
    har_path = output_dir / "sitemap.har"
    with open(har_path, "w") as f:
        json.dump(har, f, indent=2, default=str)
    print(f"Wrote {har_path} ({len(har_entries)} entries)")

    # ── URL list ───────────────────────────────────────────────────────
    url_path = output_dir / "urls.txt"
    sorted_urls = sorted(urls)
    with open(url_path, "w") as f:
        for url in sorted_urls:
            f.write(url + "\n")
    print(f"Wrote {url_path} ({len(sorted_urls)} URLs)")

    # ── Burp XML ───────────────────────────────────────────────────────
    burp_root = ET.Element("items")
    burp_root.set("burpVersion", "2024.0")
    burp_root.set("exportTime", datetime.now(tz=timezone.utc).isoformat())
    for item in burp_items:
        burp_root.append(item)

    burp_path = output_dir / "sitemap-burp.xml"
    rough = ET.tostring(burp_root, encoding="unicode", xml_declaration=True)
    parsed = minidom.parseString(rough)
    with open(burp_path, "w") as f:
        f.write(parsed.toprettyxml(indent="  "))
    print(f"Wrote {burp_path} ({len(burp_items)} items)")


if __name__ == "__main__":
    main()

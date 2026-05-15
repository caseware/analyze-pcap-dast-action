"""Convert captured HTTP exchanges to DAST-compatible site maps.

Outputs:
  - sitemap.har   (HAR 1.2 — ZAP, Burp Suite, Rapid7, Chrome DevTools)
  - urls.txt      (one URL per line — ZAP import, Rapid7 bulk add)
  - sitemap-burp.xml (Burp Suite native XML site map)

Deduplication:
  Flows from multiple captures are deduplicated by
  (method, URL, body SHA-256) so DAST scanners process each
  unique request only once.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.dom import minidom


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


def _should_include_values(
    *,
    host: str,
    status_code: int,
    method: str,
    domain_allow: list[str],
    domain_deny: list[str],
    status_codes: list[int],
    methods: list[str],
) -> bool:
    if domain_allow and not _glob_match(host, domain_allow):
        return False
    if domain_deny and _glob_match(host, domain_deny):
        return False
    if status_codes and status_code not in status_codes:
        return False
    if methods and method.upper() not in methods:
        return False
    return True


def _har_header_list(headers: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    if not headers:
        return []
    return [
        {"name": str(h.get("name", "")), "value": str(h.get("value", ""))}
        for h in headers
    ]


def _normalize_cookie_expires(value: Any) -> str | None:
    if value is None:
        return None

    s = str(value).strip()
    if not s:
        return None

    candidate = s
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", candidate):
        candidate = f"{candidate}Z"

    try:
        dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None

    # Drop sentinel/min dates that often break HAR importers.
    if dt.year <= 1:
        return None

    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sanitize_har_cookie(cookie: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {
        "name": str(cookie.get("name", "")),
        "value": str(cookie.get("value", "")),
    }

    for field in ("path", "domain", "comment", "sameSite"):
        if field in cookie and cookie[field] is not None:
            sanitized[field] = cookie[field]

    for bool_field in ("httpOnly", "secure"):
        if bool_field in cookie:
            sanitized[bool_field] = bool(cookie.get(bool_field))

    normalized_expires = _normalize_cookie_expires(cookie.get("expires"))
    if normalized_expires:
        sanitized["expires"] = normalized_expires

    return sanitized


def _sanitize_har_cookies(cookies: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not cookies:
        return []
    return [_sanitize_har_cookie(c) for c in cookies]


def _normalize_http_version(value: Any) -> str:
    candidate = str(value or "").strip()
    if re.fullmatch(r"HTTP/\d+(?:\.\d+)?", candidate):
        return candidate
    return "HTTP/1.1"


def _har_entry_to_har_entry(entry: dict[str, Any]) -> dict[str, Any]:
    started = entry.get("startedDateTime") or datetime.now(tz=timezone.utc).isoformat()
    request = entry.get("request") or {}
    response = entry.get("response") or {}

    req_body = ((request.get("postData") or {}).get("text") or "").encode("utf-8", errors="ignore")
    resp_text = ((response.get("content") or {}).get("text") or "")

    return {
        "startedDateTime": started,
        "time": int(entry.get("time") or 0),
        "request": {
            "method": request.get("method", "GET"),
            "url": request.get("url", ""),
            "httpVersion": _normalize_http_version(request.get("httpVersion")),
            "cookies": _sanitize_har_cookies(request.get("cookies") or []),
            "headers": _har_header_list(request.get("headers")),
            "queryString": request.get("queryString") or [],
            "headersSize": int(request.get("headersSize") or 0),
            "bodySize": int(request.get("bodySize") or len(req_body)),
            **(
                {
                    "postData": {
                        "mimeType": (request.get("postData") or {}).get("mimeType", ""),
                        "text": (request.get("postData") or {}).get("text", ""),
                        **(
                            {"params": (request.get("postData") or {}).get("params")}
                            if "params" in (request.get("postData") or {})
                            else {}
                        ),
                    }
                }
                if request.get("postData")
                else {}
            ),
        },
        "response": {
            "status": int(response.get("status") or 0),
            "statusText": response.get("statusText", ""),
            "httpVersion": _normalize_http_version(response.get("httpVersion")),
            "cookies": _sanitize_har_cookies(response.get("cookies") or []),
            "headers": _har_header_list(response.get("headers")),
            "content": {
                "size": int((response.get("content") or {}).get("size") or len(resp_text.encode("utf-8", errors="ignore"))),
                "mimeType": (response.get("content") or {}).get("mimeType", ""),
                "text": resp_text,
            },
            "redirectURL": response.get("redirectURL", ""),
            "headersSize": int(response.get("headersSize") or 0),
            "bodySize": int(response.get("bodySize") or 0),
        },
        "cache": entry.get("cache") or {},
        "timings": entry.get("timings") or {"send": 0, "wait": int(entry.get("time") or 0), "receive": 0},
    }


def _har_entry_to_burp_item(entry: dict[str, Any]) -> ET.Element:
    request = entry.get("request") or {}
    response = entry.get("response") or {}
    content = response.get("content") or {}

    url = str(request.get("url", ""))
    parsed = urlparse(url)
    method = str(request.get("method", "GET"))
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    path_without_query = path.split("?", 1)[0]
    request_http_version = _normalize_http_version(request.get("httpVersion"))
    response_http_version = _normalize_http_version(response.get("httpVersion"))

    item = ET.Element("item")
    started_dt = entry.get("startedDateTime") or datetime.now(tz=timezone.utc).isoformat()
    try:
        dt = datetime.fromisoformat(started_dt.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        dt = datetime.now(tz=timezone.utc)
    ET.SubElement(item, "time").text = dt.strftime("%a %b %d %H:%M:%S UTC %Y")
    ET.SubElement(item, "url").text = url
    ET.SubElement(item, "host").text = parsed.hostname or ""
    ET.SubElement(item, "port").text = str(parsed.port or (443 if parsed.scheme == "https" else 80))
    ET.SubElement(item, "protocol").text = parsed.scheme or "https"
    ET.SubElement(item, "method").text = method
    ET.SubElement(item, "path").text = path
    ET.SubElement(item, "extension").text = (
        path_without_query.rsplit(".", 1)[-1][:10] if "." in path_without_query else ""
    )

    raw_req = method + " " + path + " " + request_http_version + "\r\n"
    for h in _har_header_list(request.get("headers")):
        raw_req += h["name"] + ": " + h["value"] + "\r\n"
    raw_req += "\r\n"
    post_data = request.get("postData") or {}
    if post_data.get("text"):
        raw_req += str(post_data["text"])

    req_el = ET.SubElement(item, "request")
    req_el.set("base64", "true")
    req_el.text = base64.b64encode(raw_req.encode()).decode()

    status = int(response.get("status") or 0)
    ET.SubElement(item, "status").text = str(status)
    ET.SubElement(item, "responselength").text = str(int(response.get("bodySize") or content.get("size") or 0))
    ET.SubElement(item, "mimetype").text = str(content.get("mimeType") or "")

    raw_resp = (
        response_http_version
        + " "
        + str(status)
        + " "
        + str(response.get("statusText", ""))
        + "\r\n"
    )
    for h in _har_header_list(response.get("headers")):
        raw_resp += h["name"] + ": " + h["value"] + "\r\n"
    raw_resp += "\r\n"
    if content.get("text"):
        raw_resp += str(content["text"])

    resp_el = ET.SubElement(item, "response")
    resp_el.set("base64", "true")
    resp_el.text = base64.b64encode(raw_resp.encode()).decode()
    ET.SubElement(item, "comment")
    return item


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert captured exchanges to DAST site maps"
    )
    parser.add_argument("--captures-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--filter-domains", default="")
    parser.add_argument("--filter-exclude-domains", default="")
    parser.add_argument("--filter-status-codes", default="")
    parser.add_argument("--filter-methods", default="")
    args = parser.parse_args()

    captures_dir = Path(args.captures_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    domain_allow = _csv(args.filter_domains)
    domain_deny = _csv(args.filter_exclude_domains)
    status_codes = [int(s) for s in _csv(args.filter_status_codes)]
    methods = [m.upper() for m in _csv(args.filter_methods)]

    har_entries: list[dict] = []
    urls: set[str] = set()
    burp_items: list[ET.Element] = []
    seen: set[str] = set()

    har_files = sorted(captures_dir.glob("*.har"))
    if not har_files:
        print("::warning::No HAR capture files found in " + str(captures_dir))

    total = 0
    kept = 0
    dupes = 0
    for har_file in har_files:
        print(f"Processing {har_file.name}")
        with open(har_file, "r", encoding="utf-8") as f:
            har_data = json.load(f)

        entries = ((har_data.get("log") or {}).get("entries") or [])
        for entry in entries:
            request = entry.get("request") or {}
            response = entry.get("response") or {}
            request_url = str(request.get("url") or "")
            parsed = urlparse(request_url)
            host = parsed.hostname or ""
            method = str(request.get("method") or "GET").upper()
            status_code = int(response.get("status") or 0)

            total += 1
            if not _should_include_values(
                host=host,
                status_code=status_code,
                method=method,
                domain_allow=domain_allow,
                domain_deny=domain_deny,
                status_codes=status_codes,
                methods=methods,
            ):
                continue

            post_data = request.get("postData") or {}
            body_hash = hashlib.sha256(
                str(post_data.get("text") or "").encode("utf-8", errors="ignore")
            ).hexdigest()[:16]
            dedup_key = f"{method}\0{request_url}\0{body_hash}"
            if dedup_key in seen:
                dupes += 1
                continue
            seen.add(dedup_key)

            kept += 1
            har_entries.append(_har_entry_to_har_entry(entry))
            urls.add(request_url)
            burp_items.append(_har_entry_to_burp_item(entry))

    print(f"Processed {total} flows, kept {kept}, "
          f"deduplicated {dupes}")

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

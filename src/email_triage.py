"""Offline, rule-based triage for user-supplied RFC 5322 .eml messages.

The tool never sends mail, fetches URLs, records keystrokes, or infers emotion.
Its findings are review signals, not a phishing verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

URL_PATTERN = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
PRESSURE_PATTERN = re.compile(
    r"\b(urgent|immediately|act now|final notice|account suspended|verify your account|"
    r"password expires|payment overdue|wire transfer)\b",
    re.IGNORECASE,
)
RISKY_ATTACHMENT_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".docm", ".exe", ".hta", ".iso", ".js", ".jse",
    ".lnk", ".msi", ".pptm", ".ps1", ".scr", ".vbe", ".vbs", ".wsf", ".xlsm",
}
AUTH_FAILURES = {"fail", "softfail", "permerror"}


class LinkExtractor(HTMLParser):
    """Collect anchor destinations and their visible text without loading resources."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._active: list[tuple[str, list[str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = next((value for name, value in attrs if name.lower() == "href"), None)
            if href:
                self._active.append((href.strip(), []))

    def handle_data(self, data: str) -> None:
        for _, text_parts in self._active:
            text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._active:
            href, text_parts = self._active.pop()
            self.links.append((href, " ".join(" ".join(text_parts).split())))


def _normalized_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().rstrip(".")
    if not domain:
        return None
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return domain.lower()


def _message_domain(header_value: str | None) -> str | None:
    return _normalized_domain(parseaddr(header_value or "")[1])


def _url_host(url: str) -> tuple[str, Any] | None:
    try:
        parsed = urlsplit(url.strip().rstrip(".,;:!?)]}"))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        raw_host = parsed.hostname.rstrip(".")
        try:
            normalized = ipaddress.ip_address(raw_host).compressed.lower()
        except ValueError:
            normalized = raw_host.encode("idna").decode("ascii").lower()
        return normalized, parsed
    except (ValueError, UnicodeError):
        return None


def _visible_url_host(text: str) -> str | None:
    value = text.strip()
    if value.lower().startswith(("http://", "https://")):
        parsed = _url_host(value)
        return parsed[0] if parsed else None
    if re.fullmatch(r"(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:[/#?][^\s]*)?", value, re.IGNORECASE):
        parsed = _url_host("https://" + value)
        return parsed[0] if parsed else None
    return None


def _message_links(message: Any) -> list[tuple[str, str]]:
    links: dict[str, str] = {}
    for part in message.walk():
        if part.get_content_maintype() != "text":
            continue
        try:
            body = part.get_content()
        except (LookupError, UnicodeError):
            continue
        if not isinstance(body, str):
            continue
        if part.get_content_subtype() == "html":
            parser = LinkExtractor()
            parser.feed(body)
            for href, label in parser.links:
                links.setdefault(href, label)
        for match in URL_PATTERN.findall(body):
            links.setdefault(match.rstrip(".,;:!?)]}"), "")
    return list(links.items())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def analyze_eml(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)
    indicators: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(code: str, weight: int, evidence: str) -> None:
        key = (code, evidence)
        if key in seen:
            return
        seen.add(key)
        indicators.append({"code": code, "weight": weight, "evidence": evidence})

    from_domain = _message_domain(str(message.get("From", "")))
    reply_domain = _message_domain(str(message.get("Reply-To", "")))
    if from_domain and reply_domain and from_domain != reply_domain:
        add("reply-to-domain-mismatch", 20, f"From domain {from_domain} differs from Reply-To domain {reply_domain}.")

    for header in message.get_all("Authentication-Results", []):
        value = str(header)
        for method, status in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|permerror)\b", value, re.IGNORECASE):
            method = method.lower()
            status = status.lower()
            if status in AUTH_FAILURES:
                add(f"{method}-{status}", 18, f"Authentication-Results reports {method}={status}.")
    for header in message.get_all("Received-SPF", []):
        value = str(header)
        match = re.match(r"\s*(fail|softfail|permerror)\b", value, re.IGNORECASE)
        if match:
            status = match.group(1).lower()
            add(f"spf-{status}", 18, f"Received-SPF reports {status}.")

    subject = str(message.get("Subject", ""))
    pressure = PRESSURE_PATTERN.findall(subject)
    if pressure:
        add("urgent-subject-language", 5, "Subject contains pressure language.")

    for filename in sorted({part.get_filename() for part in message.walk() if part.get_filename()}):
        suffix = Path(filename).suffix.lower()
        if suffix in RISKY_ATTACHMENT_EXTENSIONS:
            add("risky-attachment-extension", 25, f"Attachment has a high-risk extension: {suffix}.")

    for href, label in _message_links(message):
        parsed_info = _url_host(href)
        if not parsed_info:
            continue
        host, parsed = parsed_info
        if parsed.username is not None or parsed.password is not None:
            add("credentials-in-url", 25, "A link URL contains user-info before the host.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if any(part.startswith("xn--") for part in host.split(".")):
                add("punycode-link-domain", 12, f"Link uses an IDN A-label domain: {host}.")
        else:
            add("ip-literal-link", 18, f"Link points directly to IP address {host}.")

        display_host = _visible_url_host(label)
        if display_host and display_host.removeprefix("www.") != host.removeprefix("www."):
            add("visible-link-domain-mismatch", 20, f"Visible link domain {display_host} differs from destination {host}.")

    indicators.sort(key=lambda item: (-item["weight"], item["code"], item["evidence"]))
    score = min(100, sum(item["weight"] for item in indicators))
    priority = "high" if score >= 50 else "medium" if score >= 20 else "low"
    return {
        "file": path.name,
        "sha256": _sha256(raw),
        "score": score,
        "review_priority": priority,
        "indicators": indicators,
        "indicator_count": len(indicators),
    }


def collect_eml_files(inputs: list[Path], recursive: bool) -> tuple[list[Path], list[dict[str, str]]]:
    files: dict[str, Path] = {}
    errors: list[dict[str, str]] = []
    for supplied in inputs:
        path = supplied.expanduser()
        if not path.exists():
            errors.append({"path": path.name, "error": "Path does not exist."})
            continue
        if path.is_file():
            if path.suffix.lower() == ".eml":
                files[str(path.resolve())] = path
            else:
                errors.append({"path": path.name, "error": "Expected an .eml message file."})
            continue
        if not path.is_dir():
            errors.append({"path": path.name, "error": "Path is not a regular file or directory."})
            continue
        candidates = path.rglob("*") if recursive else path.iterdir()
        found = 0
        try:
            for candidate in candidates:
                if candidate.is_file() and candidate.suffix.lower() == ".eml":
                    files[str(candidate.resolve())] = candidate
                    found += 1
        except OSError as exc:
            errors.append({"path": path.name, "error": "Could not list directory."})
        if found == 0:
            errors.append({"path": path.name, "error": "No .eml files found."})
    return sorted(files.values(), key=lambda item: str(item).casefold()), errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Triage local .eml files using transparent, offline indicators.")
    parser.add_argument("inputs", nargs="+", type=Path, metavar="PATH", help=".eml message or directory containing .eml files")
    parser.add_argument("--recursive", action="store_true", help="include .eml files in subdirectories")
    parser.add_argument("--json", action="store_true", help="print the complete JSON report to standard output")
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing JSON report")
    return parser


def render_text(report: dict[str, Any]) -> str:
    lines = ["Offline email threat triage", "=" * 27]
    for item in report["messages"]:
        lines.append(f"\n[{item['review_priority'].upper()}] {item['file']} — score {item['score']}/100")
        if not item["indicators"]:
            lines.append("  No configured indicators were found; this is not a safety verdict.")
        for indicator in item["indicators"]:
            lines.append(f"  - {indicator['code']}: {indicator['evidence']}")
    if report["errors"]:
        lines.append("\nInput errors:")
        lines.extend(f"  - {item['path']}: {item['error']}" for item in report["errors"])
    lines.append(f"\nMessages analyzed: {len(report['messages'])}; errors: {len(report['errors'])}.")
    lines.append("Heuristic score is a review priority, not a probability or malware verdict.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    files, errors = collect_eml_files(args.inputs, args.recursive)
    messages = []
    for path in files:
        try:
            messages.append(analyze_eml(path))
        except (OSError, ValueError) as exc:
            errors.append({"path": path.name, "error": f"{type(exc).__name__} while reading or parsing message."})

    report = {
        "tool": "offline-email-threat-triage",
        "messages": messages,
        "errors": errors,
        "summary": {
            "messages_analyzed": len(messages),
            "high_priority": sum(item["review_priority"] == "high" for item in messages),
            "medium_priority": sum(item["review_priority"] == "medium" for item in messages),
        },
        "limitations": [
            "Rules are indicators only and do not determine whether a message is phishing.",
            "Authentication-Results headers are trustworthy only when added by a trusted mail gateway.",
            "No URL reputation, DNS, or attachment-content scanning is performed.",
            "A low score does not mean that a message is safe.",
        ],
    }
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output.expanduser()
        input_paths = {path.resolve() for path in files}
        if output.resolve() in input_paths:
            parser.error("report output must not overwrite an input path.")
        if output.exists() and not args.overwrite:
            parser.error(f"report already exists (use --overwrite): {output}")
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(serialized, encoding="utf-8")
        except OSError as exc:
            parser.error(f"could not write report: {exc}")
    print(serialized if args.json else render_text(report), end="" if args.json else "\n")

    if errors:
        return 2
    if any(item["score"] >= 20 for item in messages):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

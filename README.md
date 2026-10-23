# Offline Email Threat Triage

A local command-line tool that reviews real RFC 5322 `.eml` messages for explainable phishing indicators. It checks sender/reply-to domain mismatches, gateway-reported authentication failures, pressure language in the subject, visible-link/destination mismatches, IP-literal or punycode link hosts, credentials embedded in URLs, and selected high-risk attachment extensions.

The tool does not generate phishing lures, collect keystrokes, infer anyone's emotions, contact URLs, or upload message contents. It uses deterministic rules rather than a trained model, so each result shows the evidence that raised its review priority.

## Requirements

- Python 3.10 or newer
- Python standard library only

No API key, model download, or network access is needed.

## Analyze one message

```powershell
python -m src.email_triage "inbox-message.eml"
```

Save a JSON report:

```powershell
python -m src.email_triage "inbox-message.eml" --output "reports/inbox-message.json"
```

Print the complete JSON report to the terminal:

```powershell
python -m src.email_triage "inbox-message.eml" --json
```

Analyze `.eml` files directly inside a folder, or add `--recursive` to include subfolders:

```powershell
python -m src.email_triage "mail-export" --recursive
```

Existing report files are protected by default. Pass `--overwrite` to replace an existing report. Run `python -m src.email_triage --help` to see all options.

## Indicators and score

Each indicator contributes a documented weight to a score capped at 100. The tool labels scores below 20 low priority, 20–49 medium, and 50 or higher high. The score is a rule-based triage priority, not a probability or a final phishing verdict.

`Authentication-Results` and `Received-SPF` headers can be forged in a raw message. Treat them as useful evidence only when a trusted mail gateway added them. Attachment checks inspect filenames only; they do not open, extract, or scan attachment contents. Link checks parse URLs but never resolve DNS or fetch the destination.

A low score does not establish that a message is safe. This tool does not use sender reputation, allowlists, gateway policy, or organization-specific context.

## Privacy

Messages are parsed locally. The JSON report contains each filename, SHA-256, indicator codes, and limited domain-level evidence; it does not copy message bodies or full email addresses. Review the report before sharing it because domains and filenames can still identify people or organizations.

## Project files

- `src/email_triage.py` — `.eml` parsing, local indicators, report generation, and CLI.
- `requirements.txt` — documents that the tool has no third-party Python dependencies.

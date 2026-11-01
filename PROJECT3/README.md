# PhishGuard – Intelligent Phishing Threat Analysis Platform
A local, rule-based phishing analyzer with a security-operations style dashboard. Python standard library only: no API keys, no databases, no machine learning, and submitted URLs are **never visited**.

## Run (Windows PowerShell)
```powershell
cd PhishGuard
python app.py            # then open http://127.0.0.1:8000
python -m unittest discover -s tests -v   # run the tests
```
Requires Python 3.9+ (no packages). To change port: `$env:PORT=8080; python app.py`.

## Architecture
| File | Role |
|---|---|
| `app.py` | HTTP server, static whitelist, `POST /api/analyze`, `GET /api/health`, error handling |
| `phishing_analyzer.py` | Orchestrates validation, detection, scoring, report |
| `keyword_detector.py` | Phrase regex rules with negation handling |
| `url_analyzer.py` | URL extraction + local heuristics (IP, shortener, lookalike, TLD, subdomains…) |
| `risk_scorer.py` | Explainable 0–100 score and 4 risk bands |
| `report_generator.py` | Summary, recommendations, TXT report |
| `index.html`, `style.css`, `script.js` | Dashboard UI (output is HTML-escaped; history in localStorage) |

Workflow: validate input → detect phrases → extract/analyse URLs → map to social-engineering techniques → score (each rule once, category cap 30, URL cap 40, combination bonus ≤12, total ≤100) → report.

## Features
Dashboard with threat distribution, message analyzer (counter, clear, loader, 6 fictional examples), phrase/URL/social-engineering tables, brand impersonation and lookalike detection, score breakdown, copy/TXT/JSON export, history with reopen/clear, threat guide, input validation (empty, non-string, >10,000 chars, bad JSON, oversize body), responsive layout, 15 unit/API tests.

## Limitations / future work
English-centric rules, negation handling is a simple 3-word window (a long-winded legitimate warning can still be flagged), small brand list, no email header/sender/attachment analysis, no reputation feeds (by design offline), heuristic scores can misjudge. Ideas: header parsing, multilingual rules, side-by-side comparison view, configurable rule files.

## Demo script (5 min)
1. Dashboard: explain the rule-based, offline design. 2. Load **Bank suspension**, analyse: walk through score ring, breakdown, URL table. 3. Load **Password reset (subtle)**: show a quieter High result driven by the lookalike domain. 4. Load **Legitimate notification**: 0/Low, and the negation rule ignoring "never ask for your OTP". 5. Download the report, open History, show the distribution chart. 6. Run the tests and close with limitations.

# PhishGuard-AI v5.0

Intelligent Hybrid Phishing URL & Website Detection System.

## Features
1. Full Hybrid Website Scan
2. Defensive AI Agent Investigation Mode
3. Gradient Boosting ML classification
4. Advanced URL feature extraction
5. DNS & WHOIS/domain intelligence
6. TLS/HTTPS certificate inspection
7. Redirect-chain analysis
8. Website content/behaviour analysis
9. Login/credential form detection
10. Social-engineering and suspicious-script signals
11. Official-domain-aware brand impersonation detection
12. QR/Quishing scanner
13. Optional VirusTotal / Google Safe Browsing reputation checks
14. FastAPI endpoint for browser extension integration
15. Scan history + JSON/TXT/PDF reports

## Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
bash setup.sh
python3 main.py
```

## Optional reputation APIs
Set `VT_API_KEY` and/or `GOOGLE_SAFE_BROWSING_API_KEY` in the environment. Without keys the scanner reports NOT CONFIGURED; it does not pretend an external lookup happened.

## Browser extension
Start API:
```bash
uvicorn api.server:app --host 127.0.0.1 --port 8000
```
Load `extension/` as an unpacked extension in a Chromium-based browser.

## ML note
The bundled model is a reproducible baseline trained from synthetic data so the project works offline. Its metrics must not be presented as real-world accuracy. For research-grade claims, train with a validated, representative phishing dataset and evaluate on a held-out test set.

## Safety
This is a defensive analysis tool. Only scan URLs/systems you are authorized to assess. It does not exploit websites.

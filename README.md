# XSW Honeypot

A **fake SAML Assertion Consumer Service (ACS) endpoint** that accepts all
incoming SAML responses without validating signatures, analyzes them for
XML Signature Wrapping (XSW) attack patterns, and provides a real-time
monitoring dashboard.

```
POST /saml/acs  ← Attacker sends crafted SAML response here
       ↓
  Base64 decode + XML parse
       ↓
  XSW Detector (XSW1–XSW8 + structural analysis)
       ↓
  Persist to Redis + disk
       ↓
  Alert webhook (Slack / Discord / custom)
       ↓
  Realistic 302 redirect (attacker stays unaware)
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Optional) Start Redis for persistent storage
docker run -d -p 6379:6379 redis:alpine

# 3. Run the honeypot
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 4. Open the dashboard
open http://localhost:8000/dashboard
```

---

## Configuration

All settings are driven by environment variables (or a `.env` file):

| Variable | Default | Description |
|---|---|---|
| `HONEYPOT_PATH` | `/saml/acs` | The fake ACS endpoint path |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `PERSIST_TO_DISK` | `true` | Also write captures to disk as `.jsonl` |
| `CAPTURES_DIR` | `captures/` | Directory for disk captures |
| `ALERT_WEBHOOK_URL` | _(empty)_ | Slack / Discord / custom webhook URL |
| `ALERT_ON_XSW_ONLY` | `false` | Only alert when XSW is suspected |
| `ALERT_MIN_SEVERITY` | `0` | Min score (0–100) to trigger alert |
| `DASHBOARD_USERNAME` | _(empty)_ | Basic auth username (leave empty to disable) |
| `DASHBOARD_PASSWORD` | _(empty)_ | Basic auth password |
| `MAX_PAYLOAD_BYTES` | `512000` | Max accepted payload size |
| `DEBUG` | `false` | Enable API docs at `/api/docs` |

Example `.env`:

```env
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
ALERT_ON_XSW_ONLY=true
ALERT_MIN_SEVERITY=20
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=changeme
PERSIST_TO_DISK=true
```

---

## Project Structure

```
xsw_honeypot/
├── app/
│   ├── main.py               # FastAPI app + lifespan
│   ├── config.py             # Pydantic settings
│   ├── models.py             # Data models (SAMLCapture, XSWAnalysis, etc.)
│   ├── routers/
│   │   ├── honeypot.py       # Fake ACS endpoint (POST /saml/acs)
│   │   └── dashboard.py      # Dashboard API (/api/stats, /api/captures)
│   ├── services/
│   │   ├── xsw_detector.py   # Core XSW detection engine
│   │   ├── saml_parser.py    # Best-effort SAML XML parser
│   │   ├── storage.py        # Redis + disk persistence
│   │   └── alerting.py       # Slack / Discord / webhook alerts
│   └── templates/
│       └── dashboard.html    # Single-page monitoring dashboard
├── tests/
│   └── test_xsw_detector.py  # Full test suite
├── requirements.txt
└── README.md
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## XSW Variants Detected

| Variant | Attack Pattern |
|---------|---------------|
| XSW1 | Signed assertion buried inside unsigned clone |
| XSW2 | Unsigned clone precedes signed assertion as sibling |
| XSW3 | Signed element wrapped in new unsigned parent |
| XSW4 | Signed element buried in a wrapper beside an unsigned assertion |
| XSW5 | Extensions block used to hide signed assertion |
| XSW6 | Signature element relocated into cloned assertion |
| XSW7 | Malicious assertion nested inside ds:KeyInfo |
| XSW8 | ds:Object element wraps the legitimate content |

---

## Dashboard

The dashboard auto-refreshes every 30 seconds and shows:
- Total captures, XSW suspected count, unique IPs, severity breakdown
- Per-capture detail: raw XML, parsed SAML fields, XSW indicators with XPath locations, variant guesses
- Statistics view with variant distribution charts

---

## Security Notes

- This honeypot **intentionally does not validate signatures** — that's the point.
- Keep the dashboard behind authentication (`DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD`) or a VPN.
- The honeypot returns a convincing 302 redirect to avoid tipping off attackers.
- Raw XML payloads are stored — treat the `captures/` directory as sensitive data.

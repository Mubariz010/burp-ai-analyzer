# Burp AI Analyzer

AI-assisted HTTP traffic triage for Burp Suite, powered by Claude. A small Burp extension
forwards in-scope traffic to a local Flask server, which asks Claude to flag issues that matter
in bug-bounty programs and builds a live map of the application.

> **Use only on targets you are authorized to test.** Captured request/response data (including
> cookies and tokens in it) is sent to the Anthropic API for analysis.

## Features
- **Passive analysis** of in-scope, non-static responses, tuned for bounty triage: severity is
  evidence-based, and won't-fix categories (missing headers, self-XSS, etc.) are suppressed
  unless they chain into real impact.
- **Deep analysis** on demand (right-click a request in Burp), with reproduction steps and
  impact statements.
- **Architecture map** of endpoints, parameters and identities, with a cross-identity IDOR
  signal (endpoint hit by 2+ distinct accounts).
- **Report drafts** from the findings you select, for writing up issues you have already
  verified manually.
- **Ask AI** tab: ask questions about the app using the collected map and findings.
- **Cost tracking** (approximate; see `PRICING_PER_MTOK` in `ai_analyzer_server.py`) and a
  local rate limit to cap API spend.
- State (findings, map, cost) persists to `data/state.json` across restarts.
- Optional shared-secret auth via `ANALYZER_TOKEN`.

## Requirements
- Docker and Docker Compose (or Python 3.11+)
- Burp Suite (any edition) with the [Jython standalone JAR](https://www.jython.org/download)
- An [Anthropic API key](https://console.anthropic.com)

## Setup

### 1. Clone and configure
```bash
git clone https://github.com/Mubariz010/http_packet_analyzer.git
cd http_packet_analyzer
cp .env.example .env
# edit .env and set ANTHROPIC_API_KEY
```

### 2. Start the server
```bash
docker compose up --build
```
Or without Docker:
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 ai_analyzer_server.py
```

### 3. Load the Burp extension
1. In Burp: **Extender → Options → Python Environment**, select the Jython JAR.
2. **Extender → Extensions → Add**, type *Python*, select `burp_ai_analyzer.py`.
3. Add your target to Burp's scope and browse it.

### 4. View results
- Findings: <http://127.0.0.1:8719/ui>
- Architecture map: <http://127.0.0.1:8719/arch>

## Configuration (`.env`)
| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | – | Required for AI analysis |
| `RATE_LIMIT` | `60` | Max Claude calls per minute |
| `ANALYZER_TOKEN` | blank | If set, API endpoints require header `X-Analyzer-Token`. Set the same value in `burp_ai_analyzer.py` |
| `HOST` | `127.0.0.1` | Bind address (Compose sets `0.0.0.0` inside the container and publishes to loopback only) |

## API
| Endpoint | Description |
|---|---|
| `POST /analyze` | Quick passive analysis |
| `POST /analyze/deep` | Deep analysis |
| `POST /report` | Draft a report from selected findings |
| `POST /ask` | Ask Claude about the app |
| `GET /findings` | All findings (JSON) |
| `GET /architecture` | Architecture map (JSON) |
| `GET /stats` | Severity counts and token/cost totals |
| `POST /clear` | Wipe findings (keeps map and cost totals) |
| `GET /ui`, `GET /arch` | Web dashboards |

## License
[MIT](LICENSE)

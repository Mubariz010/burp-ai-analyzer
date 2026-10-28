"""
ai_analyzer_server.py  —  Local AI Analysis Server
====================================================
Run this BEFORE loading the Burp extension:
    python3 ai_analyzer_server.py

Requires:
    pip install flask anthropic python-dotenv

Endpoints:
    POST /analyze        — quick passive analysis (called on every request)
    POST /analyze/deep   — deep analysis (right-click in Burp)
    POST /report         — draft a bounty-report writeup from selected, already-verified findings
    POST /ask             — ask Claude about the app (uses the architecture map + recent findings)
    GET  /findings        — JSON list of all findings
    GET  /architecture    — app map built from collected traffic
    GET  /ui               — web dashboard (Findings / Architecture / Ask AI)
    GET  /stats            — counts by severity + running token/cost totals
    POST /clear             — wipe findings (keeps the architecture map and cost totals)

If ANALYZER_TOKEN is set in .env, every endpoint above except the page shells (/, /ui, /arch)
requires header "X-Analyzer-Token: <value>". Leave it blank to keep the server open (default).
"""

import os
import json
import time
import atexit
import hashlib
import threading
from datetime import datetime
from collections import deque
from urllib.parse import unquote
from flask import Flask, request, jsonify, render_template, redirect
import anthropic
from dotenv import load_dotenv


app = Flask(__name__)


load_dotenv()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")  # <- Your API key here or in .env file
ANALYZER_TOKEN    = os.getenv("ANALYZER_TOKEN", "").strip()  # opt-in shared secret, blank = open
RATE_LIMIT        = int(os.getenv("RATE_LIMIT", "60") or "60")  # max Claude calls per minute
HOST              = os.getenv("HOST", "127.0.0.1")  # docker-compose sets 0.0.0.0 inside the container
STATE_FILE        = os.getenv("STATE_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "state.json"))

MAX_FINDINGS = 500
findings_store = deque(maxlen=MAX_FINDINGS)
findings_lock = threading.Lock()
seen_findings = set()          # (base_url, title_lower, category) already reported
seen_findings_lock = threading.Lock()
request_counter = 0
counter_lock = threading.Lock()

client = None
if ANTHROPIC_API_KEY:
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
else:
    print("[!] No ANTHROPIC_API_KEY set. Set it with:")
    print("    export ANTHROPIC_API_KEY=sk-ant-...")
    print("    Server will still run but AI analysis will be skipped.\n")

PASSIVE_MODEL = "claude-haiku-4-5-20251001"
# claude-opus-5-5 was tried here but hard-refuses this tool's pentester-framed deep-analysis
# prompt (stop_reason="refusal", zero content — 100% reproducible against the live API).
# claude-sonnet-5 handles the identical prompt/traffic normally, so it's the deep model.
DEEP_MODEL    = "claude-sonnet-5"

# USD per 1M tokens (input, output) — approximate, check https://www.anthropic.com/pricing
# for current rates and update if they change. Unknown models default to (0, 0) so cost
# tracking never crashes, it just under-reports until the table is updated.
PRICING_PER_MTOK = {
    "claude-haiku-4-5-20251001": (1.0, 5.0),
    "claude-sonnet-5":           (3.0, 15.0),
}


# ── Local rate limiting (protects your Anthropic spend/quota, independent of RateLimitError) ──

_rate_lock = threading.Lock()
_rate_window_start = time.time()
_rate_count = 0


def rate_limit_ok() -> bool:
    global _rate_window_start, _rate_count
    with _rate_lock:
        now = time.time()
        if now - _rate_window_start >= 60:
            _rate_window_start = now
            _rate_count = 0
        if _rate_count >= RATE_LIMIT:
            return False
        _rate_count += 1
        return True


# ── Token usage / cost tracking ────────────────────────────────────────────────────────────

usage_lock = threading.Lock()
usage_totals = {}  # model -> {"input": n, "output": n}


def record_usage(model: str, usage):
    if not usage:
        return
    with usage_lock:
        u = usage_totals.setdefault(model, {"input": 0, "output": 0})
        u["input"]  += getattr(usage, "input_tokens", 0) or 0
        u["output"] += getattr(usage, "output_tokens", 0) or 0


def estimate_cost_usd() -> float:
    total = 0.0
    with usage_lock:
        for model, u in usage_totals.items():
            in_rate, out_rate = PRICING_PER_MTOK.get(model, (0.0, 0.0))
            total += (u["input"] / 1_000_000) * in_rate + (u["output"] / 1_000_000) * out_rate
    return round(total, 4)


# ── Shared param parsing (used by the architecture map) ───────

def parse_params(url: str, body: str) -> dict:
    """Return {param_name: value} from a URL's query string and a JSON/form body."""
    params = {}
    if url and "?" in url:
        query = url.split("?", 1)[1]
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = unquote(v)
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if isinstance(v, (str, int, float)):
                        params[k] = str(v)
        except Exception:
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = unquote(v)
    return params


def truncate_smart(text: str, limit: int = 2000, head_ratio: float = 0.7) -> str:
    """Keep the head AND tail of long text instead of a flat cutoff — interesting fields in
    JSON bodies often sit near the end and a flat [:limit] slice silently drops them."""
    if not text:
        return ""
    if len(text) <= limit:
        return text
    head = int(limit * head_ratio)
    tail = limit - head
    dropped = len(text) - limit
    return f"{text[:head]}\n...[truncated {dropped} chars]...\n{text[-tail:]}"


def identity_hash(headers) -> str:
    """Hash the auth/cookie header so we can tell 'this endpoint was hit by 2+ distinct
    identities' without ever storing the raw token — that's the strongest passive IDOR signal."""
    auth_val, cookie_val = None, None
    for h in (headers or []):
        h = str(h)
        low = h.lower()
        if low.startswith("authorization:") and auth_val is None:
            auth_val = h
        elif low.startswith("cookie:") and cookie_val is None:
            cookie_val = h
    basis = auth_val or cookie_val
    if not basis:
        return ""
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:12]


NO_AUTH_DENIAL_HINTS = ("unauthorized", "unauthenticated", "forbidden", "access denied",
                        "not logged in", "invalid token", "invalid session", "permission denied")


def detect_unauthenticated_state_change(data: dict):
    """Deterministic check for the highest-value, purely mechanical auth signal: a state-changing
    request with no credential header at all that still succeeded. Testing showed the LLM applies
    this inconsistently even with an explicit instruction — it's not a judgment call, so it
    shouldn't be left to sampling. Returns a finding dict, or None."""
    method = (data.get("method") or "").upper()
    if method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None

    status = data.get("response_status", 0)
    if not (200 <= status < 300):
        return None

    headers = data.get("request_headers") or []
    has_credential = any(
        str(h).lower().startswith(("authorization:", "cookie:", "x-api-key:"))
        for h in headers
    )
    if has_credential:
        return None

    body_low = (data.get("response_body") or "").lower()
    if any(hint in body_low for hint in NO_AUTH_DENIAL_HINTS):
        return None  # 2xx but the body itself says access was denied — not a real bypass

    return {
        "title": "Unauthenticated state-changing request succeeded",
        "severity": "critical",
        "detail": (f"{method} {data.get('url', '')} returned {status} with no Authorization, "
                   f"Cookie, or API-key header present in the request — this state-changing "
                   f"action succeeded without any credential."),
        "category": "auth",
    }


# ── Architecture Map ──────────────────────────────────────────────────────────

app_map = {
    "endpoints":  {},   # url -> {methods, params, auth, status_codes, tech, identities}
    "tech_stack": set(),
    "parameters": {},   # param_name -> [urls where it appears]
}
app_map_lock = threading.Lock()


def update_app_map(data: dict):
    """Build a running map of the application as traffic flows in."""
    url    = data.get("url", "")
    method = data.get("method", "GET")
    status = data.get("response_status", 0)

    params = list(parse_params(url, data.get("request_body", "")).keys())
    ident  = identity_hash(data.get("request_headers"))

    # Detect authentication type from request headers
    auth = "none"
    for h in (data.get("request_headers") or []):
        h = str(h).lower()
        if "authorization: bearer" in h:   auth = "jwt/bearer"
        elif "authorization: basic" in h:  auth = "basic"
        elif "cookie:" in h:               auth = "cookie"
        elif "x-api-key" in h:             auth = "api-key"

    # Detect tech stack from response headers
    tech = []
    for h in (data.get("response_headers") or []):
        h = str(h).lower()
        for t in ["nginx", "apache", "wordpress", "php", "django",
                  "express", "spring", "laravel", "rails", "asp.net"]:
            if t in h:
                tech.append(t)

    # Use base URL without query string as map key
    base_url = url.split("?")[0]

    with app_map_lock:
        if base_url not in app_map["endpoints"]:
            app_map["endpoints"][base_url] = {
                "methods":      set(),
                "params":       set(),
                "auth":         auth,
                "status_codes": set(),
                "tech":         set(),
                "identities":   set(),
            }
        ep = app_map["endpoints"][base_url]
        ep["methods"].add(method)
        ep["params"].update(params)
        ep["status_codes"].add(status)
        ep["tech"].update(tech)
        if ident:
            ep["identities"].add(ident)
        app_map["tech_stack"].update(tech)

        # Track which URLs each parameter appears in
        for p in params:
            if p not in app_map["parameters"]:
                app_map["parameters"][p] = []
            if base_url not in app_map["parameters"][p]:
                app_map["parameters"][p].append(base_url)


# ── Prompts ───────────────────────────────────────────────────────────────────

PASSIVE_SYSTEM = """You are a triage assistant for a bug bounty hunter. Your job is narrow and
specific: catch broken access control (IDOR/BOLA) and broken authentication — the categories that
actually pay in bounty programs — plus confirmed injection. You are not writing a security audit
and you are not a compliance scanner. Most HTTP exchanges have nothing worth reporting; returning
an empty findings array is the correct, common answer.

Respond ONLY with a JSON object (no markdown, no preamble):
{
  "findings": [
    {
      "title": "Short finding name",
      "severity": "critical|high|medium|low|info",
      "detail": "One sentence: what you found and why it matters",
      "category": "injection|auth|disclosure|config|crypto|idor|xss|ssrf|other"
    }
  ]
}

HARD RULE — cookie/token/header VALUES are never, by themselves, a finding. Do not inspect what is
INSIDE a cookie, JWT, session token, or Authorization header and report on its contents (decoded
claims, a UUID, an email, "this identifies the user", "this could be used to authenticate").
That is the requester reading their own credentials — expected in every session-based app. This
covers the specific patterns that keep coming up wrong: "sensitive info/PII in cookie", "JWT
reveals user_id/email", "UUID enables tracking/enumeration". None of these are findings. The
ONLY legitimate cookie-related check is a structural attribute visible in the Set-Cookie response
header itself — missing Secure/HttpOnly/SameSite on a session-identifying cookie — and even that
is "low" severity at most and should usually be skipped per the won't-fix rule below.

Severity must reflect ONLY the evidence visible in this exchange — never guess severity from a
parameter or endpoint name alone. Default to the lowest severity that still fits the evidence:
- critical: confirmed, unauthenticated compromise visible right here — an actual secret/credential
  belonging to the backend or another party in the response body, a clear auth bypass, or an
  injected payload reflected unsanitized in a sensitive sink.
- high: strong evidence that needs one more step to weaponize — unsanitized reflection without
  confirmed exploitation, or an IDOR pattern where cross-user data is actually visible.
- medium: a real weakness with limited or conditional impact — missing auth on a low-sensitivity
  endpoint, a verbose error/stack trace that does not leak secrets.
- low: a hardening/best-practice gap with no exploitability shown here.
- info: worth noting but not a vulnerability.
Do not use critical or high unless the evidence in THIS exchange (not speculation about what could
happen) supports it.

The attacker test — apply this before writing ANY finding, not just severity: name the specific
party who is NOT supposed to have access (a different user, an anonymous visitor, etc.) and state
exactly what they gain that they shouldn't. If you cannot fill in that sentence with something
concrete from THIS exchange, do not report the finding at all — not even as low/info.

No hypotheticals — a finding must describe something you can see HAPPENED in this exchange, not
something that would be a problem IF some other condition were true. If your own reasoning for a
finding contains "if the server doesn't...", "may not be validated", "could allow", "if leaked",
"enables tracking", or similar conditional/speculative language, that is a test to run, not a
finding you observed — do not report it, at any severity. This applies directly to signatures: you
cannot tell whether a server verifies a JWT's signature just by looking at the token in a passive
exchange (you never have the server's key) — that requires actually sending a tampered/re-signed
token and observing whether it's still accepted.

A key/config value that matches a pattern meant to ship in client-side code (Firebase client
config apiKey, Google Maps browser/JS key, Stripe/reCAPTCHA publishable/site key, Supabase anon
key, and similar) is not a secret merely because it looks like one — these rely on backend-side
rules, not secrecy. Do not flag these as critical/high without a demonstrated authorization
bypass using them.

This is for bug bounty hunting, not a compliance audit. Do not surface commonly-excluded /
won't-fix categories at all — missing security headers, insecure cookie flags, clickjacking
without a sensitive state-changing action, self-XSS, logout CSRF, version/banner disclosure,
verbose errors without secrets, CORS misconfiguration without demonstrated credentialed impact,
rate-limiting gaps on non-auth endpoints. Only surface these if they combine with something else
visible here into real impact — describe the chain, not the isolated header/banner/flag.

Return an empty findings array if nothing interesting is found — this will be most of the time.
Only report things clearly visible in the data — no guessing.

Look for, in this priority order:
1. IDOR/BOLA — an object-identifying param (id/uuid/order/account/etc.) where the response in THIS
   exchange returns data that plausibly belongs to a different party than the one making the
   request (a different email, name, or account's data than the requester's own).
2. Broken authentication — this one is NOT a hypothetical, it is a direct observation, so apply it
   plainly: if request_headers contains NO Authorization, Cookie, or API-key header of any kind
   (check the whole list, not just what's summarized) AND the request is state-changing
   (POST/PUT/PATCH/DELETE) AND the response is 2xx with a body confirming the action actually
   happened (not an error/denial message) — that combination, by itself, IS the evidence. Report
   it (high or critical depending on what the action does) — do not wait for more proof, and do
   not talk yourself out of it by imagining an auth mechanism that isn't in the data you were
   given.
3. Confirmed injection — a parameter's exact value reflected unsanitized in a sensitive sink
   (HTML/JS context) in the response, or a SQL/server error string that names the underlying
   query/technology, both visible verbatim right here.
4. SSRF-shaped parameters (url/redirect/fetch/callback pointing at attacker-influenced values)
   ONLY if the response shows evidence the server actually fetched/followed it.
5. Backend secrets (not client-publishable keys) appearing in a response body, unauthenticated.
Everything else — cookie attributes, headers, tech fingerprints, generic parameter names — is not
worth reporting on its own.
"""

DEEP_SYSTEM = """You are a senior bug bounty hunter doing a deep manual review of one HTTP
exchange. Your job is narrow: broken access control (IDOR/BOLA), broken authentication, and
confirmed injection — the categories that actually pay. You are not writing a compliance audit.
If nothing in those categories is demonstrated here, return an empty "findings" array — that is a
correct, common outcome; use "suggested_next_tests" for things worth actively trying instead.

Respond ONLY with a JSON object:
{
  "findings": [
    {
      "title": "Short finding name",
      "severity": "critical|high|medium|low|info",
      "detail": "Detailed description of the issue",
      "category": "injection|auth|disclosure|config|crypto|idor|xss|ssrf|other",
      "proof_of_concept": "Specific step or payload to confirm/exploit this",
      "recommendation": "How to fix it"
    }
  ],
  "attack_surface": "2-sentence summary of what this endpoint does and its risk profile",
  "suggested_next_tests": ["test 1", "test 2", "test 3"]
}

HARD RULE — cookie/token/header VALUES are never, by themselves, a finding. Do not inspect what is
INSIDE a cookie, JWT, session token, or Authorization header and report on its contents (decoded
claims, a UUID, an email, "this identifies the user", "this could be used to authenticate"). That
is the requester reading their own credentials — expected in every session-based app. This covers
patterns that keep coming up wrong: "sensitive info/PII in cookie", "JWT reveals user_id/email",
"UUID enables tracking/enumeration". None of these are findings, at any severity.

Severity must reflect ONLY the evidence visible in this exchange — never guess severity from a
parameter or endpoint name alone. Default to the lowest severity that still fits the evidence:
- critical: confirmed, unauthenticated compromise visible right here — an actual secret/credential
  belonging to the backend or another party in the response body, a clear auth bypass, or an
  injected payload reflected unsanitized in a sensitive sink.
- high: strong evidence that needs one more step to weaponize — unsanitized reflection without
  confirmed exploitation, or an IDOR pattern where cross-user data is actually visible.
- medium: a real weakness with limited or conditional impact — missing auth on a low-sensitivity
  endpoint, a verbose error/stack trace that does not leak secrets.
- low: a hardening/best-practice gap with no exploitability shown here.
- info: worth noting but not a vulnerability.
Do not use critical or high unless the evidence in THIS exchange (not speculation about what could
happen) supports it.

The attacker test — apply this before writing ANY finding, not just severity: name the specific
party who is NOT supposed to have access (a different user, an anonymous visitor, etc.) and state
exactly what they gain that they shouldn't. If you cannot fill in that sentence with something
concrete from THIS exchange, do not put it in "findings" — put it in "suggested_next_tests"
instead (a thing worth actively trying), not both.

No hypotheticals in "findings" — a finding must describe something you can see HAPPENED in this
exchange, not something that would be a problem IF some other condition were true. If your own
reasoning contains "if the server doesn't...", "may not be validated", "could allow", "if leaked",
"enables tracking", or similar conditional/speculative language, that belongs in
"suggested_next_tests", not "findings", at any severity. This applies directly to signatures: you
cannot tell whether a server verifies a JWT's signature just by looking at the token in a passive
exchange (you never have the server's key) — that requires actually sending a tampered/re-signed
token and observing whether it's still accepted. Never claim "signature not verified" or
"alg=none accepted" as a finding unless you can see that actual tampered-token-accepted evidence
in front of you; otherwise put "try re-signing the JWT with alg=none / a tampered payload and see
if it's still accepted" in suggested_next_tests.

A key/config value that matches a pattern meant to ship in client-side code (Firebase client
config apiKey, Google Maps browser/JS key, Stripe/reCAPTCHA publishable/site key, Supabase anon
key, and similar) is not a secret merely because it looks like one — these rely on backend-side
rules, not secrecy. Do not flag these as critical/high without a demonstrated authorization
bypass using them.

This is for bug bounty hunting, not a compliance audit. Do not surface commonly-excluded /
won't-fix categories at all, even at low/info: missing security headers, insecure cookie flags,
clickjacking without a sensitive state-changing action, self-XSS, logout CSRF, version/banner
disclosure, verbose errors without secrets, CORS misconfiguration without demonstrated
credentialed impact, rate-limiting gaps on non-auth endpoints.
- These DO count if they chain into something with real impact (e.g. missing header + reflected
  input = actual XSS) — describe the chain, not the isolated weakness.
- For findings at medium/high/critical, write "proof_of_concept" as literal reproduction steps a
  triager can follow, and "recommendation" as a one-line statement of what an attacker gains
  (impact), not a generic fix suggestion.

Prioritize, in order: (1) IDOR/BOLA — object-identifying param where this exchange returns another
party's data; (2) broken authentication — a state-changing request that succeeded without valid
credentials; (3) confirmed injection — exact value reflected unsanitized in a sensitive sink, or a
verbatim SQL/server error naming the underlying system; (4) SSRF where the response shows the
server actually followed an attacker-influenced URL; (5) backend (not client-publishable) secrets
in a response body, unauthenticated. Everything else is not worth reporting on its own.
"""

REPORT_SYSTEM = """You are helping a bug bounty hunter write a submission-ready report from
findings they have ALREADY manually verified and reproduced themselves. Do not question whether
the findings are real or add new claims — only structure what is given.

For each finding, write:

## <Title>
**Severity:** <severity>
**Summary:** <1-2 sentences>
**Steps to Reproduce:**
1. ...
**Impact:** <what an attacker gains>
**Suggested remediation:** <short fix>

If multiple findings are given, separate sections with "---". Base everything only on the
information provided — do not invent request/response details that aren't given to you.
"""

ASK_SYSTEM = """You are helping a bug bounty hunter reason about a target application using ONLY
the architecture map and findings collected so far from passively observed traffic. If the given
context does not contain enough information to answer, say so plainly instead of guessing or
inventing endpoints/behavior that weren't observed. Be concise and specific — reference actual
endpoints/params from the context when relevant.
"""


# ── Claude call helper (shared by passive/deep analysis, /ask, /report) ─────────────────────

def call_claude(model: str, system: str, user_content: str, max_tokens: int):
    """Returns the raw text response, or None if the client isn't configured, the local rate
    limit was hit, or the API call failed (all logged; callers treat None as 'skip')."""
    if not client:
        return None
    if not rate_limit_ok():
        print(f"[!] Local rate limit reached ({RATE_LIMIT}/min) — skipping this AI call")
        return None
    try:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user_content}]
        )
        record_usage(model, response.usage)
        text_blocks = [b.text for b in response.content if getattr(b, "text", None)]
        if not text_blocks:
            print(f"[!] AI response had no text content (model={model})")
            return None
        return "".join(text_blocks).strip()
    except anthropic.RateLimitError:
        print("[!] Rate limited by Anthropic — slow down or use a higher tier key")
        return None
    except Exception as e:
        print(f"[!] AI error: {e}")
        return None


# ── Analysis functions ────────────────────────────────────────────────────────

def build_traffic_summary(data: dict) -> str:
    """Compact but complete representation of the HTTP exchange."""
    lines = []
    lines.append("=== REQUEST ===")
    lines.append(f"{data['method']} {data['url']}")
    for h in (data.get('request_headers') or [])[:20]:
        lines.append(str(h))
    if data.get('request_body'):
        lines.append(f"\n{truncate_smart(data['request_body'], 2000)}")

    lines.append("\n=== RESPONSE ===")
    lines.append(f"Status: {data.get('response_status', '?')}")
    for h in (data.get('response_headers') or [])[:20]:
        lines.append(str(h))
    if data.get('response_body'):
        lines.append(f"\n{truncate_smart(data['response_body'], 2000)}")

    return "\n".join(lines)


def analyze_with_ai(data: dict, deep: bool = False) -> dict:
    system = DEEP_SYSTEM if deep else PASSIVE_SYSTEM
    traffic = build_traffic_summary(data)

    raw = call_claude(
        model=DEEP_MODEL if deep else PASSIVE_MODEL,
        system=system,
        user_content=f"Analyze this HTTP exchange:\n\n{traffic}",
        max_tokens=4000 if deep else 1200,
    )
    if raw is None:
        return {"findings": []}

    # Strip markdown fences if model adds them
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error: {e}")
        return {"findings": []}


def store_finding(data: dict, result: dict):
    """Persist findings with metadata, skipping ones already reported for this endpoint."""
    url = data.get("url", "")
    base_url = url.split("?")[0]
    method = data.get("method", "GET")
    status = data.get("response_status", 0)
    timestamp = datetime.now().isoformat()

    for f in result.get("findings", []):
        dedup_key = (base_url, str(f.get("title", "")).strip().lower(), f.get("category", ""))
        with seen_findings_lock:
            if dedup_key in seen_findings:
                continue
            seen_findings.add(dedup_key)

        entry = {
            "id": int(time.time() * 1000),
            "timestamp": timestamp,
            "url": url,
            "method": method,
            "status": status,
            "host": data.get("host", ""),
            **f,
        }
        with findings_lock:
            findings_store.appendleft(entry)

    # Store extra deep-analysis fields at the top level
    if result.get("attack_surface") or result.get("suggested_next_tests"):
        meta = {
            "id": int(time.time() * 1000),
            "timestamp": timestamp,
            "url": url,
            "method": method,
            "status": status,
            "host": data.get("host", ""),
            "title": "Deep Analysis Summary",
            "severity": "info",
            "detail": result.get("attack_surface", ""),
            "category": "other",
            "suggested_next_tests": result.get("suggested_next_tests", []),
        }
        with findings_lock:
            findings_store.appendleft(meta)


# ── Persistence (JSON snapshot to disk, so findings/app_map/cost survive a restart) ─────────

_save_throttle_lock = threading.Lock()
_last_save = 0.0
SAVE_INTERVAL = 2.0  # seconds — passive traffic can be high-volume, don't hit disk every request


def _serialize_state() -> dict:
    with findings_lock:
        findings_snapshot = list(findings_store)
    with seen_findings_lock:
        seen_snapshot = [list(k) for k in seen_findings]
    with app_map_lock:
        endpoints = {}
        for url, d in app_map["endpoints"].items():
            endpoints[url] = {
                "methods":      list(d["methods"]),
                "params":       list(d["params"]),
                "auth":         d["auth"],
                "status_codes": list(d["status_codes"]),
                "tech":         list(d["tech"]),
                "identities":   list(d["identities"]),
            }
        app_map_snapshot = {
            "endpoints":  endpoints,
            "tech_stack": list(app_map["tech_stack"]),
            "parameters": dict(app_map["parameters"]),
        }
    with usage_lock:
        usage_snapshot = {m: dict(u) for m, u in usage_totals.items()}
    return {
        "findings":        findings_snapshot,
        "seen_findings":   seen_snapshot,
        "app_map":         app_map_snapshot,
        "request_counter": request_counter,
        "usage_totals":    usage_snapshot,
    }


def _write_state_to_disk():
    try:
        os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(_serialize_state(), fh)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print(f"[!] Failed to save state: {e}")


def save_state(force: bool = False):
    global _last_save
    now = time.time()
    with _save_throttle_lock:
        if not force and (now - _last_save) < SAVE_INTERVAL:
            return
        _last_save = now
    _write_state_to_disk()


def load_state():
    global request_counter
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE) as fh:
            saved = json.load(fh)
    except Exception as e:
        print(f"[!] Failed to load saved state ({e}) — starting fresh")
        return

    with findings_lock:
        findings_store.extend(saved.get("findings", []))
    with seen_findings_lock:
        seen_findings.update(tuple(k) for k in saved.get("seen_findings", []))
    with app_map_lock:
        saved_map = saved.get("app_map", {})
        for url, d in saved_map.get("endpoints", {}).items():
            app_map["endpoints"][url] = {
                "methods":      set(d.get("methods", [])),
                "params":       set(d.get("params", [])),
                "auth":         d.get("auth", "none"),
                "status_codes": set(d.get("status_codes", [])),
                "tech":         set(d.get("tech", [])),
                "identities":   set(d.get("identities", [])),
            }
        app_map["tech_stack"] = set(saved_map.get("tech_stack", []))
        app_map["parameters"] = saved_map.get("parameters", {})
    with usage_lock:
        for m, u in saved.get("usage_totals", {}).items():
            usage_totals[m] = {"input": u.get("input", 0), "output": u.get("output", 0)}
    request_counter = saved.get("request_counter", 0)
    print(f"[i] Restored {len(findings_store)} findings and "
          f"{len(app_map['endpoints'])} endpoints from {STATE_FILE}")


atexit.register(_write_state_to_disk)


# ── Auth gate (opt-in — blank ANALYZER_TOKEN keeps the server exactly as open as before) ────

PROTECTED_PREFIXES = ("/analyze", "/findings", "/architecture", "/stats", "/clear",
                       "/ask", "/report")


@app.before_request
def check_token():
    if not ANALYZER_TOKEN:
        return
    if not request.path.startswith(PROTECTED_PREFIXES):
        return  # page shells (/, /ui, /arch) stay reachable by plain browser navigation
    if request.headers.get("X-Analyzer-Token") != ANALYZER_TOKEN:
        return jsonify({"error": "missing or invalid X-Analyzer-Token"}), 401


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    global request_counter
    data = request.get_json(force=True)
    with counter_lock:
        request_counter += 1
    update_app_map(data)
    result = analyze_with_ai(data, deep=False)
    deterministic = detect_unauthenticated_state_change(data)
    if deterministic:
        result.setdefault("findings", []).insert(0, deterministic)
    if result.get("findings"):
        store_finding(data, result)
    save_state()
    return jsonify(result)


@app.route("/analyze/deep", methods=["POST"])
def analyze_deep():
    data = request.get_json(force=True)
    update_app_map(data)
    result = analyze_with_ai(data, deep=True)
    deterministic = detect_unauthenticated_state_change(data)
    if deterministic:
        result.setdefault("findings", []).insert(0, deterministic)
    if result.get("findings"):
        store_finding(data, result)
    save_state()
    return jsonify(result)


@app.route("/report", methods=["POST"])
def report():
    """Drafts a submission-shaped writeup from findings YOU select — meant for findings you've
    already manually verified, not a substitute for that verification."""
    body = request.get_json(force=True) or {}
    ids = body.get("finding_ids") or []
    if not ids:
        return jsonify({"error": "provide finding_ids (select findings in the UI first)"}), 400

    with findings_lock:
        items = list(findings_store)
    selected = [f for f in items if f.get("id") in ids]
    if not selected:
        return jsonify({"error": "no matching findings"}), 404

    clean = [{k: v for k, v in f.items() if not k.startswith("_")} for f in selected]
    draft = call_claude(
        model=DEEP_MODEL,
        system=REPORT_SYSTEM,
        user_content=f"Findings (already manually verified by the hunter):\n{json.dumps(clean, indent=2)}",
        max_tokens=3000,
    )
    save_state(force=True)  # persist token/cost usage even though findings weren't mutated
    if draft is None:
        return jsonify({"error": "AI unavailable — check ANTHROPIC_API_KEY / rate limit"}), 503
    return jsonify({"report": draft})


@app.route("/ask", methods=["POST"])
def ask():
    body = request.get_json(force=True) or {}
    question = (body.get("question") or "").strip()
    if not question:
        return jsonify({"error": "provide a 'question'"}), 400

    with app_map_lock:
        endpoints = app_map["endpoints"]
        context_lines = [
            f"Tech stack: {', '.join(app_map['tech_stack']) or 'unknown'}",
            f"Total endpoints observed: {len(endpoints)}",
        ]
        for url, d in list(endpoints.items())[:80]:
            context_lines.append(
                f"- {','.join(sorted(d['methods']))} {url} | auth={d['auth']} | "
                f"params={','.join(sorted(d['params'])) or 'none'} | "
                f"status={','.join(str(s) for s in sorted(d['status_codes']))} | "
                f"identities_seen={len(d['identities'])}"
            )
    with findings_lock:
        recent = list(findings_store)[:30]
    findings_lines = [
        f"- [{f.get('severity')}] {f.get('title')} @ {f.get('url')}: {f.get('detail', '')}"
        for f in recent
    ]

    context = ("ARCHITECTURE MAP:\n" + "\n".join(context_lines) +
               "\n\nRECENT FINDINGS:\n" + ("\n".join(findings_lines) or "(none yet)"))

    answer = call_claude(
        model=DEEP_MODEL,
        system=ASK_SYSTEM,
        user_content=f"{context}\n\nQuestion: {question}",
        max_tokens=1500,
    )
    save_state(force=True)  # persist token/cost usage even though findings weren't mutated
    if answer is None:
        return jsonify({"error": "AI unavailable — check ANTHROPIC_API_KEY / rate limit"}), 503
    return jsonify({"answer": answer})


@app.route("/findings", methods=["GET"])
def get_findings():
    severity = request.args.get("severity")
    host = request.args.get("host")
    category = request.args.get("category")

    with findings_lock:
        items = list(findings_store)

    if severity:
        items = [f for f in items if f.get("severity") == severity]
    if host:
        items = [f for f in items if host in f.get("host", "")]
    if category:
        items = [f for f in items if f.get("category") == category]

    return jsonify(items)


@app.route("/stats", methods=["GET"])
def stats():
    with findings_lock:
        items = list(findings_store)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories = {}
    hosts = {}
    for f in items:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        cat = f.get("category", "other")
        categories[cat] = categories.get(cat, 0) + 1
        h = f.get("host", "unknown")
        hosts[h] = hosts.get(h, 0) + 1

    with usage_lock:
        tokens_snapshot = {m: dict(u) for m, u in usage_totals.items()}

    return jsonify({
        "total": len(items),
        "requests_analyzed": request_counter,
        "by_severity": counts,
        "by_category": categories,
        "by_host": hosts,
        "cost_usd": estimate_cost_usd(),
        "tokens": tokens_snapshot,
    })


@app.route("/clear", methods=["POST"])
def clear():
    global request_counter
    with findings_lock:
        findings_store.clear()
    with seen_findings_lock:
        seen_findings.clear()
    request_counter = 0
    save_state(force=True)
    return jsonify({"ok": True})


@app.route("/architecture", methods=["GET"])
def architecture():
    with app_map_lock:
        # Convert sets to lists for JSON serialization
        endpoints = {}
        for url, data in app_map["endpoints"].items():
            endpoints[url] = {
                "methods":      list(data["methods"]),
                "params":       list(data["params"]),
                "auth":         data["auth"],
                "status_codes": list(data["status_codes"]),
                "tech":         list(data["tech"]),
                "identity_count": len(data["identities"]),
            }
        return jsonify({
            "total_endpoints": len(endpoints),
            "tech_stack":      list(app_map["tech_stack"]),
            "endpoints":       endpoints,
            "parameters":      dict(app_map["parameters"]),
            "interesting": {
                "no_auth":     [u for u, d in endpoints.items()
                                if d["auth"] == "none" and
                                any(m in d["methods"] for m in ["POST", "PUT", "DELETE"])],
                "file_params": [p for p in app_map["parameters"]
                                if any(x in p.lower() for x in
                                ["file", "path", "url", "redirect", "next", "src", "img"])],
                "id_params":   [p for p in app_map["parameters"]
                                if any(x in p.lower() for x in
                                ["id", "uid", "user", "account", "order", "uuid"])],
                "cross_identity_idor": [
                    u for u, d in endpoints.items()
                    if d["identity_count"] >= 2 and
                    any(x in p.lower() for p in d["params"] for x in
                        ["id", "uid", "user", "account", "order", "uuid"])
                ],
            }
        })


# ── Web UI ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect("/ui")

@app.route("/ui")
def ui():
    return render_template("ui.html", token=ANALYZER_TOKEN)

@app.route("/arch")
def architecture_ui():
    return render_template("arch.html", token=ANALYZER_TOKEN)

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_state()

    print("=" * 55)
    print("  AI Traffic Analyzer Server")
    print("=" * 55)
    print(f"  API Key  : {'set ✓' if ANTHROPIC_API_KEY else 'NOT SET ✗'}")
    print(f"  Passive  : {PASSIVE_MODEL}")
    print(f"  Deep     : {DEEP_MODEL}")
    print(f"  Auth     : {'required (ANALYZER_TOKEN set)' if ANALYZER_TOKEN else 'open (set ANALYZER_TOKEN in .env to lock it down)'}")
    print(f"  Rate cap : {RATE_LIMIT} AI calls/min")
    print(f"  State    : {STATE_FILE}")
    print(f"  Server   : http://127.0.0.1:8719")
    print(f"  Web UI   : http://127.0.0.1:8719/ui")
    print("=" * 55)
    print("\n  1. Start this server")
    print("  2. Load burp_ai_analyzer.py in Burp → Extender")
    print("  3. Browse your target — findings appear live\n")

    app.run(host=HOST, port=8719, debug=False, threaded=True)

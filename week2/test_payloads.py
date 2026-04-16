import requests
import json

BASE_URL = "http://localhost:5000"  # change port if different

# ── change this to your actual endpoint name ──────────────────────────
ENDPOINT = "/predict"   # try /api/analyze or /api/predict if this 404s
# ──────────────────────────────────────────────────────────────────────

test_cases = [
    # ── BENIGN (expect: allow / low) ──────────────────────────────────
    ("SELECT id, name FROM users WHERE id = 42",                             "benign",           "allow"),
    ("SELECT * FROM products WHERE category = 'Electronics' ORDER BY price", "benign",           "allow"),
    ("INSERT INTO logs (event, ip) VALUES ('login', '192.168.1.1')",         "benign",           "allow"),
    ("UPDATE profiles SET last_login = NOW() WHERE user_id = 7",             "benign",           "allow"),
    ("john.doe@example.com",                                                  "benign",           "allow"),
    ("New York",                                                              "benign",           "allow"),

    # ── FLAG / MEDIUM ─────────────────────────────────────────────────
    ("admin'--",                                                              "boolean-based",    "medium"),
    ("1 OR 1=1",                                                              "boolean-based",    "medium"),
    ("SELECT * FROM users",                                                   "mass-dump",        "medium"),
    ("' OR 'x'='x",                                                          "boolean-based",    "medium"),

    # ── HIGH / CHALLENGE ─────────────────────────────────────────────
    ("1' AND SLEEP(5)--",                                                     "time-based",       "high"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",                        "error-based",      "high"),
    ("1; UPDATE users SET password='hacked' WHERE 1=1--",                    "stacked-query",    "high"),
    ("' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",           "error-based",      "high"),
    ("SeLeCt * fRoM uSeRs wHeRe iD=1 oR 1=1--",                             "obfuscated",       "high"),

    # ── BLOCK / CRITICAL ─────────────────────────────────────────────
    ("' UNION SELECT username, password FROM users--",                        "union-based",      "critical"),
    ("1 UNION ALL SELECT NULL, NULL, NULL--",                                 "union-based",      "critical"),
    ("' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--", "union-based", "critical"),
    ("WAITFOR DELAY '0:0:5'--",                                              "time-based",       "critical"),
    ("1; DROP TABLE users--",                                                 "stacked-query",    "critical"),
    ("1; EXEC xp_cmdshell('whoami')--",                                      "stacked-query",    "critical"),
    ("' UNION SELECT username,password,3 FROM users INTO OUTFILE '/tmp/dump.txt'--", "exfiltration", "critical"),
    ("' OR 1=1; INSERT INTO users(username,password) VALUES('hacker','pwned')--", "stacked-bool", "critical"),

    # ── WAF BYPASS / OBFUSCATED ───────────────────────────────────────
    ("%27%20OR%201%3D1--",                                                    "url-encoded",      "critical"),
    ("0x554e494f4e2053454c454354204e554c4c2c4e554c4c2d2d",                   "hex-encoded",      "critical"),
    ("SE/**/LECT/**/*/**/FR/**/OM/**/users",                                  "comment-frag",     "high"),
    ("1%2527%2520OR%25201%253D1--",                                           "double-url-enc",   "critical"),
    ("Robert'); DROP TABLE students--",                                       "second-order",     "critical"),

    # ── EDGE CASES ────────────────────────────────────────────────────
    ("''",                                                                    "edge-case",        "allow"),
    ("SELECT 1",                                                              "edge-case",        "allow"),
]

# ── colour helpers ────────────────────────────────────────────────────
RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"

def colour(text, risk):
    r = (risk or "").lower()
    if r in ("allow", "low"):        return f"{GREEN}{text}{RESET}"
    if r in ("flag", "medium"):      return f"{YELLOW}{text}{RESET}"
    return f"{RED}{text}{RESET}"

def pass_fail(expected, actual):
    # loose match — just check allow vs non-allow
    exp_safe = expected == "allow"
    act_safe = actual in ("allow", "low")
    if exp_safe == act_safe:
        return f"{GREEN}PASS{RESET}"
    return f"{RED}FAIL{RESET}"

# ── run ───────────────────────────────────────────────────────────────
print(f"\n{BOLD}TriGuard v2 — 30 Test Cases{RESET}")
print(f"Endpoint: {BASE_URL}{ENDPOINT}\n")
print(f"{'#':<4} {'Category':<18} {'Expected':<10} {'Got':<12} {'Score':<8} {'PF':<6}  Payload")
print("─" * 110)

passed = failed = errors = 0

for i, (payload, category, expected) in enumerate(test_cases, 1):
    try:
        resp = requests.post(
            f"{BASE_URL}{ENDPOINT}",
            json={"query": payload},
            timeout=10
        )
        if resp.status_code != 200:
            print(f"{i:<4} {category:<18} {expected:<10} {RED}HTTP {resp.status_code}{RESET}")
            errors += 1
            continue

        d = resp.json()
        risk  = d.get("risk") or d.get("risk_level") or d.get("severity") or "?"
        score = d.get("prob") or d.get("final_score") or d.get("ml_score") or 0.0
        pf    = pass_fail(expected, risk)

        if "PASS" in pf: passed += 1
        else:            failed += 1

        short_payload = (payload[:55] + "…") if len(payload) > 55 else payload
        print(f"{i:<4} {category:<18} {expected:<10} "
              f"{colour(risk.upper()[:10], risk):<20} "
              f"{float(score):<8.4f} {pf:<6}  {CYAN}{short_payload}{RESET}")

    except requests.exceptions.ConnectionError:
        print(f"\n{RED}ERROR: Cannot connect to {BASE_URL} — is Flask running?{RESET}")
        break
    except Exception as e:
        print(f"{i:<4} {category:<18} {RED}ERROR: {e}{RESET}")
        errors += 1

print("─" * 110)
print(f"\n{BOLD}Results: {GREEN}{passed} passed{RESET}  {RED}{failed} failed{RESET}  {YELLOW}{errors} errors{RESET} / {len(test_cases)} total\n")

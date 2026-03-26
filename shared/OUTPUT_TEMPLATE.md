# Phase-4 Auditor Output Template (Fill-in Style)

> **All Phase-4 Auditors MUST strictly follow this template to generate `exploits/{sink_id}.json`.**
> This template is the fill-in version of `schemas/exploit_result.schema.json`. The LLM only needs to replace 【填写】 with actual content.
> Hard constraints are defined in `shared/output_standard.md`.

---

## ⛔ Output Iron Rules

1. **File path**: `$WORK_DIR/exploits/{sink_id}.json` — one file per Sink, MUST NOT merge
2. **JSON syntax**: execute `python3 -m json.tool exploits/{sink_id}.json` before submission; syntax error → do not submit
3. **Field completeness**: all `required` fields MUST be present and non-empty; missing fields → QA rejection
4. **【填写】 cleared**: at submission time `grep '【填写】' exploits/{sink_id}.json` MUST return 0 matches
5. **auth_matrix read-only**: `auth_requirement` MUST strictly match the `auth_level` for that route in `auth_matrix.json`; MUST NOT modify auth judgments independently
6. **evidence_score ↔ severity consistency**: score ≥ 2.10 → evidence_score ≥ 7; 1.20-2.09 → 4-6; < 1.20 → 1-3

---

## JSON Fill-in Template

```json
{
  "sink_id": "【填写：e.g. sink_042】",
  "route_url": "【填写：e.g. /api/user/profile】",
  "sink_function": "【填写：e.g. mysqli_query, include, exec】",
  "specialist": "【填写：this Auditor's name, e.g. sqli_auditor】",
  "route_type": "【填写：A=high-risk unauthenticated / B=authenticated / C=indirect call】",
  "rounds_executed": "【填写：actual number of attack rounds executed, 1-8】",
  "rounds_skipped": "【填写：number of rounds skipped, 0-8】",
  "skip_reason": "【填写：reason for skipping, null if none】",

  "results": [
    {
      "round": 1,
      "strategy": "【填写：strategy name, e.g. classic single-quote probing】",
      "payload": "【填写：complete payload actually sent】",
      "injection_point": "【填写：injection point, e.g. GET param id / POST body username / Cookie session_id】",
      "request": "【填写：complete HTTP request, Burp style, including Host/Cookie/Content-Type headers】",
      "response_status": "【填写：HTTP status code, e.g. 200】",
      "response_body_snippet": "【填写：first 500 characters of response body】",
      "evidence_type": "【填写：evidence type, e.g. error_based / time_based / blind_boolean, null if none】",
      "evidence_detail": "【填写：evidence detail, e.g. response contains SQL syntax error near..., null if none】",
      "result": "【填写：confirmed / suspected / failed】",
      "failure_reason": "【填写：failure reason, null if successful】"
    }
  ],

  "final_verdict": "【填写：confirmed / suspected / potential / not_vulnerable】",
  "confidence": "【填写：high / medium / low】",
  "evidence_score": "【填写：integer 1-10, corresponding to severity.score range】",

  "evidence": {
    "EVID_XXX_FIRST": "【填写：first evidence point, e.g. app/Models/User.php:89 — DB::select(\"SELECT * FROM...\")】",
    "EVID_XXX_SECOND": "【填写：second evidence point, refer to the EVID list for this vulnerability type in shared/evidence_contract.md】"
  },

  "trace": {
    "source": "【填写：user input source, e.g. $_GET['id']】",
    "sink": "【填写：dangerous function, e.g. mysqli_query($conn, $sql)】",
    "call_chain": "【填写：complete call chain, e.g. Controller::show() → Model::findRaw() → DB::select()】",
    "taint_flow": "【填写：taint propagation path, e.g. $id(unfiltered) → $sql(concatenated) → mysqli_query(executed)】"
  },

  "severity": {
    "reachability": "【填写：integer 0-3】",
    "reachability_reason": "【填写：justification, e.g. this route has no auth middleware, accessible by anyone】",
    "impact": "【填写：integer 0-3】",
    "impact_reason": "【填写：justification, e.g. can read all user table data including password hashes】",
    "complexity": "【填写：integer 0-3】",
    "complexity_reason": "【填写：justification, e.g. can be triggered by a single GET request, no WAF】",
    "score": "【填写：calculated result of R×0.40 + I×0.35 + C×0.25】",
    "cvss": "【填写：calculated result of (score / 3.0) × 10.0】",
    "level": "【填写：C / H / M / L (mapped by score range)】",
    "vuln_id": "【填写：e.g. C-SQL-001, format {Level}-{Type}-{Sequence}】"
  },

  "prerequisite_conditions": {
    "auth_requirement": "【填写：anonymous / authenticated / admin / internal_network — MUST match auth_matrix】",
    "bypass_method": "【填写：auth bypass method, e.g. IDOR via user_id param, null if none】",
    "other_preconditions": ["【填写：preconditions, e.g. APP_DEBUG=true, empty array [] if none】"],
    "exploitability_judgment": "【填写：directly_exploitable / conditionally_exploitable / not_exploitable】"
  }
}
```

---

## Downgrade Rules (Auditors MUST Execute These)

| Condition | Downgrade Action |
|-----------|-----------------|
| `exploitability_judgment = "not_exploitable"` | `final_verdict` MAY be at most `potential`, `confidence` MAY be at most `low` |
| `exploitability_judgment = "conditionally_exploitable"` | `severity.complexity` SHOULD be reduced by 1 level |
| Any EVID annotated with `[未获取: reason]` | `final_verdict` MUST be downgraded from `confirmed` to `suspected` |
| `evidence_score < 7` | `final_verdict` MUST NOT be `confirmed` |

---

## Special Field Notes

### race_condition_results (only filled by race_condition_auditor)
```json
{
  "race_condition_results": {
    "tested": true,
    "concurrent_requests": "【填写：number of concurrent requests】",
    "result": "【填写：vulnerable / not_vulnerable】",
    "detail": "【填写：race condition result description】"
  }
}
```
Other Auditors MUST set this field to `null`.

### Evidence Field EVID Naming
- Refer to the EVID list for the corresponding vulnerability type in `shared/evidence_contract.md`
- Each EVID value = `file_path:line_number — code snippet or description`
- If an EVID cannot be obtained, fill in `[未获取: specific reason]`; MUST NOT leave empty or omit

---

## Pre-Submission Check Commands

```bash
# 1. JSON syntax validation
python3 -m json.tool "$WORK_DIR/exploits/${SINK_ID}.json" > /dev/null 2>&1 && echo "✅ JSON valid" || echo "❌ JSON invalid"

# 2. Placeholder remnant detection
grep -c '【填写】' "$WORK_DIR/exploits/${SINK_ID}.json" | grep -q '^0$' && echo "✅ No placeholders" || echo "❌ Placeholders remain"

# 3. Required field check
python3 -c "
import json, sys
with open(sys.argv[1]) as f: d = json.load(f)
required = ['sink_id','route_url','sink_function','specialist','route_type','rounds_executed','results','final_verdict','confidence','evidence','severity','prerequisite_conditions']
missing = [k for k in required if k not in d or d[k] is None]
print('✅ All required fields present' if not missing else f'❌ Missing: {missing}')
" "$WORK_DIR/exploits/${SINK_ID}.json"
```

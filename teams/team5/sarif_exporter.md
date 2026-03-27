> **Skill ID**: S-091 | **Phase**: 5 | **Role**: Convert vulnerability results to SARIF 2.1.0 format
> **Input**: exploits/*.json, correlation_report.json, priority_queue.json
> **Output**: 报告/audit_report.sarif.json

# SARIF-Exporter — Fill-in Template

---

## 1. Identity

| Field | Value |
|-------|-------|
| Skill ID | S-091 |
| Skill Name | SARIF-Exporter |
| Phase | 5 — Reporting |
| Purpose | Convert all Phase-4 exploit results into a SARIF 2.1.0 JSON file for IDE / CI-CD consumption |
| Agent Persona | You are the SARIF Exporter agent. You read exploit results and produce a spec-compliant SARIF report. |

---

## 2. Input Contract

| # | Parameter | Source | Required | Description |
|---|-----------|--------|----------|-------------|
| 1 | `WORK_DIR` | Orchestrator | ✅ Yes | Absolute path to the working directory |
| 2 | `$WORK_DIR/exploits/*.json` | Phase-4 specialists | ✅ Yes (≥0 files) | Vulnerability verification results; directory may be empty |
| 3 | `$WORK_DIR/correlation_report.json` | Phase-4.5 correlator | ❌ Optional | Post-exploitation correlation analysis report |
| 4 | `$WORK_DIR/priority_queue.json` | Phase-2 prioritiser | ❌ Optional | CVSS scores, priority levels, supplemental metadata |

---

## 3. CRITICAL Rules

1. Output MUST conform to **SARIF 2.1.0** (`$schema` URL + `"version": "2.1.0"`).
2. Every `result` entry MUST contain `ruleId`, `level`, `message`, and `locations`.
3. `level` MUST be one of: `error`, `warning`, `note`.
4. All `startLine` values MUST be positive integers (≥ 1).
5. Output file MUST be valid, pretty-printed JSON (2-space indent).
6. Only exploit results with `final_verdict` ∈ {`confirmed`, `suspected`, `potential`} produce a SARIF result.
7. Warnings MUST be recorded in `invocations[0].toolExecutionNotifications`.
8. If validation fails → fix and re-output. MUST NOT output invalid SARIF.

---

## 4. Fill-in Procedure

### Procedure A — Collect Inputs

```bash
ls "$WORK_DIR/exploits/"*.json 2>/dev/null
```

Fill in the availability table:

| # | File / Directory | Exists? (Y/N) | Action if Missing |
|---|------------------|---------------|-------------------|
| 1 | `$WORK_DIR/exploits/` (directory) | `____` | Warn → generate empty SARIF (`runs[0].results = []`) |
| 2 | `$WORK_DIR/exploits/*.json` (≥1 file) | `____` | Warn → generate empty SARIF |
| 3 | `$WORK_DIR/correlation_report.json` | `____` | Warn → skip correlation enhancement, continue normally |
| 4 | `$WORK_DIR/priority_queue.json` | `____` | Warn → leave `priority` and `cvss_score` empty in properties |

---

### Procedure B — Map Tool Info

Fill in the SARIF `runs[0].tool.driver` fields:

| Field | Fill-in Value |
|-------|---------------|
| `name` | `"php-audit"` |
| `version` | `"2.0.0"` |
| `semanticVersion` | `"2.0.0"` |
| `informationUri` | `"https://github.com/php-audit"` |
| `rules` | *(populated in Procedure F)* |

Top-level scaffold:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { /* fields above */ } },
    "results": [],
    "invocations": [{
      "executionSuccessful": true,
      "startTimeUtc": "____",
      "endTimeUtc": "____"
    }]
  }]
}
```

---

### Procedure C — Map Each Exploit to SARIF Result

For **each** exploit JSON whose `final_verdict` ∈ {`confirmed`, `suspected`, `potential`}, fill in one row set:

| JSON Field | Source | Fill-in Value |
|------------|--------|---------------|
| `ruleId` | Specialist name → type (`sqli_auditor` → `sqli`, `rce_auditor` → `rce`, etc.) | `____` |
| `level` | Procedure D mapping table | `____` |
| `message.text` | Exploit result: sink function, route, conclusion | `"____"` |
| `locations[0].physicalLocation.artifactLocation.uri` | `context_pack` or exploit result → relative file path | `"____"` |
| `locations[0].physicalLocation.region.startLine` | Exploit result or `priority_queue.json` → line number | `____` |
| `codeFlows` | Procedure E (or `[]` if no trace chain) | `____` |
| `properties.priority` | `priority_queue.json` → `P0`/`P1`/`P2`/`P3` | `"____"` |
| `properties.specialist` | Exploit result → specialist agent name | `"____"` |
| `properties.cvss_score` | `priority_queue.json` → CVSS 3.1 score | `____` |
| `properties.confidence` | Exploit result → `high`/`medium`/`low` | `"____"` |
| `properties.sink_id` | Exploit result → sink identifier | `"____"` |
| `properties.rounds_executed` | Exploit result → number of test rounds | `____` |
| `properties.evidence_summary` | Exploit result → key evidence summary | `"____"` |

Repeat for every qualifying exploit result.

---

### Procedure D — Severity Mapping

| `final_verdict` | SARIF `level` | SARIF `kind` |
|-----------------|---------------|--------------|
| `confirmed` | `error` | `fail` |
| `suspected` | `warning` | `review` |
| `potential` | `note` | `review` |

---

### Procedure E — Build codeFlows

If the `context_pack` associated with an exploit result contains a taint trace chain (source → intermediates → sink), fill in `threadFlowLocations`:

| Step | `artifactLocation.uri` | `region.startLine` | `message.text` | Fill-in Value |
|------|------------------------|--------------------|-----------------|---------------|
| 1 — Source | Source file path | Source line no. | `"User input source: $_GET/$_POST/..."` | `____` |
| 2 — Propagation | Intermediate file path | Intermediate line no. | `"Data propagation: <function call description>"` | `____` |
| 3 — Sink | Sink file path | Sink line no. | `"Dangerous sink: <function name>"` | `____` |

Resulting JSON structure:

```json
"codeFlows": [{
  "threadFlows": [{
    "locations": [
      { "location": { "physicalLocation": { "artifactLocation": { "uri": "____" }, "region": { "startLine": ____ } }, "message": { "text": "____" } } },
      { "location": { "physicalLocation": { "artifactLocation": { "uri": "____" }, "region": { "startLine": ____ } }, "message": { "text": "____" } } },
      { "location": { "physicalLocation": { "artifactLocation": { "uri": "____" }, "region": { "startLine": ____ } }, "message": { "text": "____" } } }
    ]
  }]
}]
```

- If no `context_pack` is associated → set `codeFlows` to `[]`.

---

### Procedure F — Generate Rules Array

Collect all distinct `ruleId` values from Procedure C. For each unique type, fill in one rule:

| Rule Field | Fill-in Value |
|------------|---------------|
| `id` | `"____"` (e.g. `sqli`, `rce`, `xss`, `lfi`, `ssrf`, `upload`, `deserial`) |
| `name` | `"____"` (e.g. `SQL Injection`) |
| `shortDescription.text` | `"____"` (e.g. `SQL Injection vulnerability`) |
| `helpUri` | `"____"` (CWE URL, e.g. `https://cwe.mitre.org/data/definitions/89.html`) |
| `properties.tags` | `["security", "____"]` |

Known type → CWE mapping reference:

| Type | CWE | helpUri |
|------|-----|---------|
| `sqli` | CWE-89 | `https://cwe.mitre.org/data/definitions/89.html` |
| `rce` | CWE-78 | `https://cwe.mitre.org/data/definitions/78.html` |
| `xss` | CWE-79 | `https://cwe.mitre.org/data/definitions/79.html` |
| `lfi` | CWE-98 | `https://cwe.mitre.org/data/definitions/98.html` |
| `ssrf` | CWE-918 | `https://cwe.mitre.org/data/definitions/918.html` |
| `upload` | CWE-434 | `https://cwe.mitre.org/data/definitions/434.html` |
| `deserial` | CWE-502 | `https://cwe.mitre.org/data/definitions/502.html` |

---

### Procedure G — Validate Output

After generating the SARIF JSON, fill in the checklist:

| # | Check | Pass/Fail |
|---|-------|-----------|
| 1 | Top-level contains `"version": "2.1.0"` and `runs` array | `____` |
| 2 | `runs[0].tool.driver.name` === `"php-audit"` | `____` |
| 3 | Every result has `ruleId`, `level`, `message`, `locations` | `____` |
| 4 | Every `level` value ∈ {`error`, `warning`, `note`} | `____` |
| 5 | Every `startLine` is a positive integer (≥ 1) | `____` |
| 6 | Output file is valid JSON (parseable) | `____` |
| 7 | All warnings recorded in `invocations[0].toolExecutionNotifications` | `____` |

If **any** check = `Fail` → fix the issue and re-validate. MUST NOT output invalid SARIF.

---

## 5. Output Contract

| Field | Value |
|-------|-------|
| File Path | `$WORK_DIR/报告/audit_report.sarif.json` |
| Format | JSON, 2-space indentation |
| Spec | SARIF 2.1.0 |
| Contents | `runs[0].results` = one entry per qualifying exploit; `runs[0].tool.driver.rules` = one entry per unique vuln type |

---

## 6. Examples

### ✅ GOOD — Complete SARIF result with codeFlows

```json
{
  "ruleId": "sqli",
  "level": "error",
  "message": {
    "text": "Confirmed SQL Injection in mysqli_query() via route POST /api/user/login"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "app/Models/UserModel.php" },
      "region": { "startLine": 42 }
    }
  }],
  "codeFlows": [{
    "threadFlows": [{
      "locations": [
        { "location": { "physicalLocation": { "artifactLocation": { "uri": "public/index.php" }, "region": { "startLine": 15 } }, "message": { "text": "User input source: $_POST['username']" } } },
        { "location": { "physicalLocation": { "artifactLocation": { "uri": "app/Controllers/AuthController.php" }, "region": { "startLine": 78 } }, "message": { "text": "Data propagation: AuthController::login() passes $username" } } },
        { "location": { "physicalLocation": { "artifactLocation": { "uri": "app/Models/UserModel.php" }, "region": { "startLine": 42 } }, "message": { "text": "Dangerous sink: mysqli_query()" } } }
      ]
    }]
  }],
  "properties": {
    "priority": "P0",
    "specialist": "sqli_auditor",
    "cvss_score": 9.8,
    "confidence": "high",
    "sink_id": "sink_001",
    "rounds_executed": 3,
    "evidence_summary": "UNION-based injection returned database version string in response body"
  }
}
```

### ❌ BAD — Missing ruleId, empty codeFlows when trace exists, wrong level

```json
{
  "level": "critical",
  "message": { "text": "SQL Injection found" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "app/Models/UserModel.php" },
      "region": { "startLine": 42 }
    }
  }],
  "codeFlows": []
}
```

**Problems:**
1. `ruleId` is **missing** — every result MUST have `ruleId`.
2. `level` is `"critical"` — invalid; must be `error`, `warning`, or `note`.
3. `codeFlows` is `[]` even though a taint trace chain exists in the context_pack.
4. `properties` block is **missing** — must include priority, specialist, confidence, etc.

---

## 7. Error Handling

| # | Scenario | Handling | Notification Level |
|---|----------|----------|--------------------|
| 1 | `exploits/` directory does not exist | Warn → generate empty SARIF (`results = []`) | `warning` |
| 2 | Single exploit JSON parse failure | Warn → skip that file, continue processing others | `warning` |
| 3 | `correlation_report.json` does not exist | Warn → skip correlation enhancement, generate normally | `warning` |
| 4 | `priority_queue.json` does not exist | Warn → leave `priority` and `cvss_score` empty in properties | `warning` |
| 5 | `context_pack` file missing | Warn → set `codeFlows` to `[]` | `warning` |
| 6 | File path cannot be resolved | Use `"unknown"` as the `uri` | `warning` |

All warnings MUST be appended to `invocations[0].toolExecutionNotifications`:

```json
"toolExecutionNotifications": [{
  "level": "warning",
  "message": { "text": "<warning description>" }
}]
```

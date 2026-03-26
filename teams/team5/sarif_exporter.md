> **Skill ID**: S-091 | **Phase**: 5 | **Role**: Convert vulnerability results to SARIF 2.1.0 format
> **Input**: exploits/*.json, correlation_report.json, priority_queue.json
> **Output**: 报告/audit_report.sarif.json

# SARIF-Exporter

You are the SARIF Exporter agent, responsible for converting all vulnerability verification results into standard SARIF 2.1.0 format for IDE integration and CI/CD pipeline consumption.

## Input

- `WORK_DIR`: Working directory path
- `$WORK_DIR/exploits/*.json` (Phase-4 specialist agent vulnerability verification results)
- `$WORK_DIR/correlation_report.json` (optional, Phase-4.5 post-exploitation correlation analysis report)
- `$WORK_DIR/priority_queue.json` (Phase-2 priority queue, used to supplement CVSS and other metadata)

## Responsibilities

Read all exploit results and generate a structured report following the SARIF 2.1.0 specification.

---

## Step 1: Collect Input Data

```bash
# Read all exploit results
ls "$WORK_DIR/exploits/"*.json 2>/dev/null
```

- If the `exploits/` directory does not exist or is empty → output a warning and generate an empty SARIF (containing only tool information, runs[0].results = [])
- If `correlation_report.json` does not exist → warn and continue; this does not affect the main workflow
- If `priority_queue.json` does not exist → warn and continue; leave CVSS / priority fields empty

## Step 2: SARIF 2.1.0 Structure Mapping

The output file MUST conform to the following top-level structure:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "php-audit",
        "version": "2.0.0",
        "informationUri": "https://github.com/php-audit",
        "rules": []
      }
    },
    "results": [],
    "invocations": [{
      "executionSuccessful": true,
      "startTimeUtc": "ISO 8601 timestamp",
      "endTimeUtc": "ISO 8601 timestamp"
    }]
  }]
}
```

### Tool Information

- `driver.name`: `"php-audit"`
- `driver.version`: `"2.0.0"`
- `driver.rules`: Generate one rule entry for each vulnerability type (id is the sink_type, e.g., `sqli`, `rce`)

### Result Mapping Rules

Each exploit result with a `final_verdict` of `confirmed`, `suspected`, or `potential` → maps to one SARIF result:

```json
{
  "ruleId": "vulnerability type (inferred from specialist: sqli_auditor→sqli, rce_auditor→rce, etc.)",
  "level": "severity mapping (see below)",
  "message": {
    "text": "vulnerability description including sink function name, route, and verification conclusion"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {
        "uri": "relative file path (extracted from context_pack or exploit results)"
      },
      "region": {
        "startLine": "line number (extracted from exploit results or priority_queue)"
      }
    }
  }],
  "codeFlows": [],
  "properties": {}
}
```

### Severity Mapping

| final_verdict | SARIF level |
|---------------|-------------|
| confirmed     | error       |
| suspected     | warning     |
| potential     | note        |

### codeFlows Generation

If the context_pack associated with the exploit result contains a call chain (source→sink), generate codeFlows:

```json
"codeFlows": [{
  "threadFlows": [{
    "locations": [
      {
        "location": {
          "physicalLocation": {
            "artifactLocation": { "uri": "source file" },
            "region": { "startLine": "source line number" }
          },
          "message": { "text": "User input source: $_GET/$_POST/..." }
        }
      },
      {
        "location": {
          "physicalLocation": {
            "artifactLocation": { "uri": "intermediate function file" },
            "region": { "startLine": "intermediate line number" }
          },
          "message": { "text": "Data propagation: function call description" }
        }
      },
      {
        "location": {
          "physicalLocation": {
            "artifactLocation": { "uri": "sink file" },
            "region": { "startLine": "sink line number" }
          },
          "message": { "text": "Dangerous sink: function name" }
        }
      }
    ]
  }]
}]
```

- When no context_pack is associated → leave codeFlows as an empty array

### properties Extension

Each result's `properties` field MUST contain:

```json
"properties": {
  "priority": "P0/P1/P2/P3 (from priority_queue.json)",
  "specialist": "name of the specialist agent that performed verification",
  "cvss_score": "CVSS 3.1 score (from priority_queue.json)",
  "confidence": "high/medium/low",
  "sink_id": "associated sink_id",
  "rounds_executed": "number of test rounds executed",
  "evidence_summary": "key evidence summary"
}
```

### Rules Array Generation

Generate `driver.rules` entries for all encountered vulnerability types:

```json
{
  "id": "sqli",
  "name": "SQL Injection",
  "shortDescription": { "text": "SQL Injection vulnerability" },
  "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
  "properties": {
    "tags": ["security", "sql-injection"]
  }
}
```

## Step 3: Error Handling

| Scenario | Handling |
|----------|---------|
| exploits/ directory does not exist | Warn + generate empty SARIF |
| Single exploit JSON parse failure | Warn + skip the file, continue processing others |
| correlation_report.json does not exist | Warn + skip correlation enhancement, generate normally |
| priority_queue.json does not exist | Warn + leave priority and CVSS empty in properties |
| context_pack file missing | Warn + leave codeFlows empty |
| File path cannot be resolved | Use "unknown" as the uri |

All warnings MUST be recorded in the SARIF `invocations[0].toolExecutionNotifications`:

```json
"toolExecutionNotifications": [{
  "level": "warning",
  "message": { "text": "warning description" }
}]
```

## Step 4: Output Validation

After generation, perform basic structural validation:

1. Top level MUST contain `version: "2.1.0"` and a `runs` array
2. `runs[0].tool.driver.name` MUST be `"php-audit"`
3. Every result MUST contain `ruleId`, `level`, `message`, and `locations`
4. `level` value MUST be `error`, `warning`, or `note`
5. All `physicalLocation.region.startLine` values MUST be positive integers
6. Output file MUST be valid JSON

If validation fails → fix and re-output. MUST NOT output invalid SARIF.

## Output

File: `$WORK_DIR/报告/audit_report.sarif.json`

Ensure the output is formatted JSON (2-space indentation) for ease of manual review.

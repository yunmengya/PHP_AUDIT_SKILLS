# Anti-Hallucination Rules

The following 17 rules are hard constraints for all Agents. Violating any single rule will cause the Agent's output to be rejected by QC.

---

## Rule 1: MUST NOT Speculate on Code Behavior

- When describing code behavior, **MUST cite the specific file path + line number**
- Format: `file_path:line_number`, e.g., `app/Http/Controllers/UserController.php:45`
- MUST NOT use vague assertions like "might", "probably", or "generally" to describe code behavior
- If the file has not been read, use the Read tool to read it first before describing

## Rule 2: Conclusions MUST Include Source Code Snippets

- Every analysis conclusion **MUST include a corresponding source code snippet** as evidence
- Source code snippets MUST be actual content read from the file; fabrication is MUST NOT
- Format requirements: include file path, line number range, and actual code
- **Structured evidence**: Every conclusion MUST reference EVID_* evidence point IDs defined in `shared/evidence_contract.md`; see that file for details
- **Trace-Gate hard threshold**: Sinks with trace_status=UNRESOLVED/INCOMPLETE → maximum "suspected"; Sinks without a trace file → maximum "unverified". Only trace_status=RESOLVED + all required EVIDs present → "confirmed" is allowed
- Example:
  ```
  // app/Service/CmdService.php:45-47
  public function execute($command) {
      return system($command);  // Sink: user input flows directly into system()
  }
  ```

## Rule 3: Mark as "[Needs Verification]" When Uncertain

- When **uncertain** about a conclusion, MUST mark it with `[Needs Verification]`
- MUST NOT present uncertain analysis results as definitive conclusions
- Items marked `[Needs Verification]` will be reviewed by subsequent Agents or QC
- Certainty levels: Confirmed > Highly Suspected > Needs Verification

## Rule 4: Every Link in a Call Chain MUST Have Code Evidence

- When describing a Source → Sink call chain, **every link MUST have actual code evidence**
- MUST NOT skip steps (e.g., "user input → ... → system()" — the ... MUST NOT be omitted)
- Each link MUST include: file path, function name, line number, how parameters are passed
- If a link cannot be confirmed, mark it as `[Chain Break: reason]`; MUST NOT pretend continuity

## Rule 5: Payload Results MUST Be Judged from Actual Responses

- After sending a Payload, **MUST judge results based on the actual HTTP response**
- MUST NOT assume "Payload executed successfully" without checking the response
- MUST record: HTTP status code, response body (key parts), response time
- Time-based blind injection MUST compare against baseline response time

## Rule 6: Expected vs Actual Response Mismatch = Failure

- When expected and actual responses **do not match**, the test MUST be marked as **failed**
- MUST NOT rationalize as "although the response doesn't match, the vulnerability may still exist"
- Failed tests MAY serve as input for strategy adjustment in the next round
- Only when the actual response clearly confirms the vulnerability's existence SHALL it be marked as success

## Rule 7: MUST NOT Describe Code from Memory

- When analyzing code, **MUST re-read the file** to confirm its content
- MUST NOT describe code based on previously read memory (the code may have been modified during analysis)
- Each time code is referenced, use the Read tool to read the latest content
- For multiple references to the same file within the same analysis step, reusing a single read result is acceptable

## Rule 8: Analyze "Non-Vulnerability Possibility" When Reporting Vulnerabilities

- When reporting a vulnerability, **MUST simultaneously provide an analysis of "why this might not be a vulnerability"**
- Non-vulnerability factors to consider:
  - Whether global middleware/WAF has already intercepted it
  - Whether parameters have already been filtered/escaped by upstream functions
  - Whether the PHP version has already patched this exploitation method
  - Whether the framework has built-in protection mechanisms
  - Whether the Sink is only called within admin-only functionality
- Provide the final determination after comprehensive evaluation

## Rule 9: When Multiple Agents Report the Same Issue, Physical Evidence Takes Precedence

- When multiple Agents provide different conclusions on the same issue:
  - **Conclusions with physical evidence > conclusions without physical evidence**
  - MUST NOT decide by "voting" (3 Agents saying it's a vulnerability ≠ it is a vulnerability)
  - Evidence standards: actual HTTP requests/responses, file changes within the container, database changes
- Conflicting conclusions MUST note the disagreement in the report

## Rule 10: Confirmed Vulnerabilities MUST Have Complete Reproduction Materials

- Vulnerabilities marked as ✅ (confirmed) **MUST provide**:
  - Complete HTTP request (directly replayable in Burp/curl)
  - Complete HTTP response (proving the vulnerability was triggered)
  - If container state changes are involved: docker exec verification command + output
- Missing any of the above → downgrade to ⚠️ (Highly Suspected)
- ⚠️ and ⚡ level vulnerabilities do not require complete reproduction materials, but the reason MUST be stated

## Rule 11: Race Condition Tests MUST Be Statistically Significant

- Race condition vulnerabilities **MUST be determined based on statistical significance**; MUST NOT assert from a single request
- Minimum requirement: success rate > 30% across at least 20 concurrent tests to be marked as "confirmed"
- MUST record: concurrency count, total requests, success count, success rate, time window
- A single sporadic success = "Needs Verification"; MUST NOT be marked as "confirmed"
- MUST rule out false positives caused by network jitter and normal retries

## Rule 12: NoSQL/GraphQL Injection MUST Differentiate Query Semantics

- NoSQL injection MUST **prove that query semantics have been altered**; MUST NOT rely solely on operators appearing in the response
- MongoDB operator injection: MUST compare result differences between normal queries vs injected queries
- GraphQL injection: MUST prove that depth/batch/introspection queries returned **data beyond authorized scope**
- MUST NOT treat GraphQL Schema introspection itself as a vulnerability (unless introspection exposes sensitive field definitions)
- Redis CRLF injection: MUST prove that additional commands were executed (e.g., confirmed via INFO response)

## Rule 13: Business Logic Vulnerabilities Require Complete Business Context

- Business logic vulnerabilities **MUST describe the complete business flow** and the bypassed step
- Price tampering: MUST prove that the tampered price was **actually used in a transaction** (not just frontend display)
- Flow skipping: MUST prove that the **final state was persisted** after skipping intermediate steps
- MUST NOT equate "frontend-modifiable parameters" directly with "business logic vulnerability" (backend validation MUST be verified)
- Negative value/overflow tests: MUST prove that balance/inventory data was actually abnormally modified

## Rule 14: Cryptographic Vulnerabilities MUST Consider Practical Exploitability

- Weak hashing algorithms (MD5/SHA1) SHOULD only be marked as vulnerabilities when **used for password storage or signature verification**
- MD5 used for cache keys, file checksums, or other non-security contexts ≠ cryptographic vulnerability
- Predictable random numbers: MUST prove that the **prediction window is exploitable in a realistic attack scenario**
- JWT weak keys: MUST **actually crack the key** or prove `alg:none` is accepted; MUST NOT rely solely on theoretical possibility
- Timing attacks: MUST prove timing differences are measurable **in a network environment** (not locally)

## Rule 15: WordPress Audits MUST Distinguish Core/Plugin/Theme

- WordPress vulnerabilities MUST **clearly indicate the affected scope**: core, specific plugin (with version), or specific theme (with version)
- Plugin/theme vulnerabilities are not equivalent to WordPress core vulnerabilities
- CVE matching MUST verify whether the **currently installed version** falls within the affected range
- Nonce bypass MUST prove that the **actual operation was executed**; MUST NOT assert CSRF success merely because the Nonce is predictable
- XML-RPC `system.multicall` amplification: MUST prove that rate limiting was actually bypassed

## Rule 16: MUST NOT Fabricate Results When Tool Calls Fail

- When Bash/Read/Search or other tools **fail or time out**, **MUST NOT pretend success and fabricate output**
- After a tool failure, MUST:
  1. Record the failure reason (error message, timeout, insufficient permissions, etc.)
  2. Mark the step as `[Tool Failure: reason]`
  3. Attempt alternative approaches (different command/path/fallback strategy)
  4. If all alternatives fail, mark as `[Cannot Verify]` and skip that Sink
- MUST NOT infer results based on "experience" after tool failure

## Rule 17: Output Content MUST Be Kept Within Reasonable Limits

- A single Agent's JSON output **MUST NOT exceed 500KB**
- Code snippet citations MUST be limited to **the essential 10 lines or fewer**; MUST NOT paste entire files
- Call chain descriptions MUST NOT exceed **10 levels**; beyond that, collapse intermediate levels and mark as `[...N intermediate calls omitted...]`
- HTTP response Body SHOULD retain only **key evidence portions** (first 500 characters + key matching lines); MUST NOT paste the full content
- Output exceeding size limits will be truncated by QC and marked as `[Output Exceeded Limit: needs reduction]`
